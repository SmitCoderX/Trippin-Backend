from flask import Flask, jsonify, request, make_response, redirect, url_for, send_from_directory, abort
import pymongo
import bcrypt, jwt, datetime, uuid, os
from functools import wraps
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = 'E:\Study\Final_project\images'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secretkeylol'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] =  2 * 1024 * 1024

myClient = pymongo.MongoClient("mongodb+srv://shinchan:cvcvpo123@mycluster1.fzgzf.mongodb.net/tripin?retryWrites=true&w=majority",ssl=True,ssl_cert_reqs='CERT_NONE')
mydb = myClient["tripin"]
users = mydb["user_data"]

# ---------------------------------------------------///////       User routes      ///////////-------------------------------------------------


def token_verify(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        

        if not token:
            return jsonify({
                'message': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.find_one({"username": data['username']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        
        return f(current_user, *args, **kwargs)

    return decorated

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/register', methods = ['POST'])
def register():
    qry = {'username': request.args['username']}
    existing_user = users.find_one(qry)

    if existing_user:
        return jsonify({'message':"user already exists"})
        
    else:
        
        #hashpass = bcrypt.hashpw(request.args['password'].encode('utf-8'), bcrypt.gensalt(10))
        salt = bcrypt.gensalt(10)
        hashpass =  bcrypt.hashpw(request.args['password'].encode('utf-8'),salt)

        users.insert({
            "_id": str(uuid.uuid4()),
            'username': request.args['username'],
            "password": hashpass,
            "name": request.args["name"],
            "email": request.args["email"],
            "mobile_no": request.args["mobile_no"],
            #"image_data": "profimg.jpg",
            })
        return jsonify({'message':"user registered successfully"})


@app.route('/login', methods = ['POST'])
def login():
    login_name = users.find_one({"username": request.args["username"]})
    
    if login_name:
        if bcrypt.checkpw(request.args['password'].encode('utf-8'), login_name['password']):
            token = jwt.encode({'username': login_name['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours = 24)}, app.config['SECRET_KEY'], algorithm="HS256") 
            
            return make_response(jsonify({
                'message': "Login Successfull",
                'token' : token
                }), 201)
        else:
            return jsonify({'message':"username or password does not match"})

    else:
        return make_response("user not exists", 401)


@app.route('/me', methods = ['GET'])
@token_verify
def me(current_user):
    user = users.find_one({"username": current_user['username']})

    me_data = {
        "_id": user['_id'],
        "username": user['username'],
        "name": user['name'],
        "email": user['email'],
        "mobile_no": user['mobile_no'],
    }

    return jsonify(me_data)

@app.route('/images', methods=['GET', 'POST'])
@token_verify
def upload_file(current_user):
    user = users.find_one({"username": current_user['username']})

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"message":'no file part'})

        file = request.files['file']

        if file.filename == '':
            return jsonify({"message":'no file selected'})

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            #file.save(os.path.join(app.config['UPLOAD_FOLDER'], user['_id']) + '.' + filename.rsplit('.', 1)[1].lower())
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], user['_id']) + '.jpg')
            return jsonify({"message":'file uploaded successfully'})

    elif request.method == 'GET':

        img = user['_id']
        img = f"{img}.jpg"
        #return str(img)
        try:
            return send_from_directory(app.config["UPLOAD_FOLDER"], filename=img, as_attachment=True)
        except FileNotFoundError:
            abort(404)

@app.route('/me', methods = ['PUT'])
@token_verify
def me_update(current_user):
    user = users.find_one({"username": current_user['username']})
    myQuery = {"username": user['username']}
    newValues = {"$set": {
        "name": request.args['name'],
        "email": request.args['email'],
        "mobile_no": request.args['mobile_no']
    }}
    users.update_one(myQuery, newValues)
    return jsonify({'message': "updated successfully"})

@app.route('/me', methods = ['DELETE'])
@token_verify
def delete_user(current_user):
    user = users.find_one({"username": current_user['username']})
    myQuery = {"username": user['username']}
    users.delete_one(myQuery)
    return jsonify({'message': "record deleted successfully"})



# ---------------------------------------------//////////          Business routes         //////////------------------------------------------------

# @app.route('/business_register', methods = ['POST'])
# def business_register():
#     qry = {'username': request.args['username']}
#     existing_user = users.find_one(qry)

#     if existing_user:
#         return jsonify({'message':"user already exists"})
        
#     else:
#         salt = bcrypt.gensalt(10)
#         hashpass =  bcrypt.hashpw(request.args['password'].encode('utf-8'),salt)

#         users.insert({
#             "_id": str(uuid.uuid4()),
#             'username': request.args['username'],
#             "password": hashpass,
#             "name": request.args["name"],
#             "email": request.args["email"],
#             "mobile_no": request.args["mobile_no"],
#             })
#         return jsonify({'message':"user registered successfully"})


if __name__ == "__main__":
    app.run(debug=True)