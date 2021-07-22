from flask import Flask, jsonify, request, make_response, redirect, url_for
import pymongo
import bcrypt, jwt, datetime, uuid
from functools import wraps
import gridfs, codecs

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secretkeylol'

myClient = pymongo.MongoClient("mongodb+srv://shinchan:cvcvpo123@mycluster1.fzgzf.mongodb.net/tripin?retryWrites=true&w=majority",ssl=True,ssl_cert_reqs='CERT_NONE')
mydb = myClient["tripin"]
users = mydb["user_data"]
gf = gridfs.GridFS(mydb)
#user_login = mydb["user_login"]

# ---------------------------------------------------///////       User routes      ///////////-------------------------------------------------


def token_verify(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        # token = request.args.get('token')
        #print(token)

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
    #qry = ({"username": request.args["username"]})
    login_name = users.find_one({"username": request.args["username"]})
    
    if login_name:
        if bcrypt.checkpw(request.args['password'].encode('utf-8'), login_name['password']):
            token = jwt.encode({'username': login_name['username'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours = 24)}, app.config['SECRET_KEY'], algorithm="HS256") 
            # dashboard(login_name)
            #return dashboard(login_name['username'])
            # return jsonify({
            #     'message': 'login successful',
            #     'token': token
            # })
            return make_response(jsonify({'token' : token}), 201)
        else:
            return jsonify({'message':"user does not match"})

    else:
        return make_response("user not verify", 401)


@app.route('/me', methods = ['GET'])
@token_verify
def me(current_user):
    user = users.find_one({"username": current_user['username']})

    #img = user['image_data']

    if not 'image_data' in user:
        image = "no_image.jpg"
    else:
        img = user['image_data']
        image = gf.get(img['_id'])
        base64_data = codecs.encode(image.read(), 'base64')
        image = base64_data.decode('utf-8')

    me_data = {
        "_id": user['_id'],
        "username": user['username'],
        "name": user['name'],
        "email": user['email'],
        "mobile_no": user['mobile_no'],
        "image":image
    }

    return jsonify(me_data)

@app.route('/image', methods=["PUT"])
@token_verify
def saveImage(current_user):
    user = users.find_one({"username": current_user['username']})
    myQuery = {"username": user['username']}
    #if 'image' in request.files:
    image = request.files['image']
    pic_name = request.form.get('pic_name')
    id = gf.put(image, filename=pic_name)
    query = {"$set":{
        "image_data":{
            '_id': id,
            'pic_name': pic_name,
    }}}
    status = users.update_one(myQuery, query)
    if status:
        return jsonify({'result': 'Image uploaded successfully'}), 201
    return jsonify({'result': 'Error occurred during uploading'}), 500

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
        
#         #hashpass = bcrypt.hashpw(request.args['password'].encode('utf-8'), bcrypt.gensalt(10))
#         salt = bcrypt.gensalt(10)
#         hashpass =  bcrypt.hashpw(request.args['password'].encode('utf-8'),salt)

#         users.insert({
#             "_id": str(uuid.uuid4()),
#             'username': request.args['username'],
#             "password": hashpass,
#             "name": request.args["name"],
#             "email": request.args["email"],
#             "mobile_no": request.args["mobile_no"],
#             #"image_data": "profimg.jpg",
#             })
#         return jsonify({'message':"user registered successfully"})


if __name__ == "__main__":
    app.run(debug=True)