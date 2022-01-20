from flask import Flask, json, jsonify, request, make_response, redirect, url_for, send_from_directory, abort
import pymongo
import bcrypt, jwt, datetime, uuid, os
from functools import wraps
#from pymongo import message
from werkzeug.utils import secure_filename


UPLOAD_FOLDER = 'E:\Study\Final_project\images'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secretkeylol'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] =  2 * 1024 * 1024

myClient = pymongo.MongoClient("mongodb+srv://smit:cvcvpo123@tripin.vlfo9.mongodb.net/tripin?retryWrites=true&w=majority",ssl=True,ssl_cert_reqs='CERT_NONE')
mydb = myClient["tripin"]
users = mydb["user_data"]
Rdata = mydb["review_data"]

# ---------------------------------------------------///////       Token Verification      ///////////-------------------------------------------------


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
            current_user = users.find_one({"_id": data['_id']})
        except:
            return jsonify({'message': 'Token is invalid!'}), 403
        
        return f(current_user, *args, **kwargs)

    return decorated


# ---------------------------------------------------///////       file extension verification      ///////////-------------------------------------------------


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------------------------------------------------///////       Average ratings calculation      ///////////-------------------------------------------------


def avg_ratings(lst, business_id):

    count = len(lst)
    total = sum(lst)
    avg = total / count
    result = round(avg, 1)

    myQuery = {"_id": business_id}

    new_data = {"$set":{"average_ratings": result}}
    
    status = users.update_one(myQuery, new_data)
    if status:
        return True

    return False


# ---------------------------------------------------///////       User register route      ///////////-------------------------------------------------


@app.route('/user_register', methods = ['POST'])
def register():
    qry = {'username': request.args['username']}
    existing_user = users.find_one(qry)

    if existing_user:
        return jsonify({'message':"user already exists"})
        
    else:
        
        #hashpass = bcrypt.hashpw(request.args['password'].encode('utf-8'), bcrypt.gensalt(10))
        salt = bcrypt.gensalt(10)
        hashpass =  bcrypt.hashpw(request.args['password'].encode('utf-8'),salt)

        id = str(uuid.uuid4())
        img_url = "http://100.25.142.90/static/images/" + id + ".jpg"

        status = users.insert({
            "_id": id,
            'username': request.args['username'],
            "password": hashpass,
            "name": request.args["name"],
            "email": request.args["email"],
            "mobile_no": request.args["mobile_no"],
            "role": "user",
            "image": img_url,
            })
        if status:
            return jsonify({'message':"user registered successfully"})
        
        return jsonify({"message":"Request cannot be processed. Please  try again later"})


# ---------------------------------------------------///////       User/Businees login route      ///////////-------------------------------------------------


@app.route('/login', methods = ['POST'])
def login():
    login_data = ({
        "username": request.args['username'],
        "password": request.args['password'],
        })
    
    login_name = users.find_one({"username": login_data["username"]})

    if login_name:
        if bcrypt.checkpw(login_data['password'].encode('utf-8'), login_name['password']):
            token = jwt.encode({'_id': login_name['_id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours = 720)}, app.config['SECRET_KEY'], algorithm="HS256") 
            
            return make_response(jsonify({
                'message': "Login Successfull",
                'token' : token
                }), 201)
        else:
            return jsonify({'message':"username or password does not match"})

    else:
        return make_response("user not found", 401)


# ---------------------------------------------------///////       Route for sending user/business data      ///////////-------------------------------------------------


@app.route('/me', methods = ['GET'])
@token_verify
def me(current_user):
    
    user = users.find_one({"_id": current_user["_id"]})

    json_data = {}

    for keys in user:
        if keys == "password":
            pass 
        else:
            json_data[keys] = user[keys]

    if json_data:
        return jsonify(json_data)

    else:
        return jsonify({"message":"request cannot be processed, please try again!!"})


# ---------------------------------------------------///////       Route for uploading images      ///////////-------------------------------------------------


@app.route('/upload_images', methods=['POST'])
@token_verify
def upload_file(current_user):
    user = users.find_one({"_id": current_user['_id']})

    if request.method == 'POST':
        if 'file' not in request.files:
            return jsonify({"message":'no file part'})

        file = request.files['file']

        if file.filename == '':
            return jsonify({"message":'no file selected'})

        if file and allowed_file(file.filename):
            new_name =user['_id'] + '.jpg'
            filename = secure_filename(new_name)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return jsonify({"message":'file uploaded successfully'})


# ---------------------------------------------------///////       Route to update User/business info       ///////////-------------------------------------------------


@app.route('/update', methods = ['PUT'])
@token_verify
def me_update(current_user):
   
    user = users.find_one({"_id": current_user["_id"]})

    myQuery = {"_id": user['_id']}

    get_new_data =  request.get_json()
    new_data = {"$set":{}}

    for key in get_new_data:
        new_data["$set"][key] = get_new_data[key]

    
    status = users.update_one(myQuery, new_data)
    if status:
        return jsonify({'message': "updated successfully"})

    return jsonify({"message":"request cannot be processed, please try again!!"})


# ---------------------------------------------------///////       Account deletion route      ///////////-------------------------------------------------


@app.route('/delete_user', methods = ['DELETE'])
@token_verify
def delete_user(current_user):
    
    user = users.find_one({"_id": current_user["_id"]})

    myQuery = {"_id": user['_id']}
    status = users.delete_one(myQuery)

    if status:
        return jsonify({'message': "record deleted successfully"})

    return jsonify({"message":"request cannot be processed, please try again!!"})




# ---------------------------------------------//////////          Business register route         //////////------------------------------------------------

@app.route('/business_register', methods = ['POST'])
def business_register():
    qry = {'username': request.args['username']}
    existing_user = users.find_one(qry)

    if existing_user:
        return jsonify({'message':"user already exists"})
        
    else:
        salt = bcrypt.gensalt(10)
        hashpass =  bcrypt.hashpw(request.args['password'].encode('utf-8'),salt)
        id = str(uuid.uuid4())
        img_url = "http://100.25.142.90/static/images/" + id + ".jpg"

        status = users.insert({
            "_id": id,
            "username": request.args["username"],
            "password": hashpass,
            "name": request.args["name"],
            "email": request.args["email"],
            "mobile_no": request.args["mobile_no"],
            "address": request.args["address"],
            "desc": request.args["desc"],
            "city": request.args["city"],
            "type": request.args["type"],
            "role": "business",
            "image": img_url,
            "average_ratings": 0.0,
            })

        if status:
            return jsonify({'message':"business registered successfully"})

        return jsonify({"message":'please try again'})


# ---------------------------------------------------///////       Route to get nearby places      ///////////-------------------------------------------------


@app.route('/places', methods = ['GET'])
def places():
    loc = request.args['city']

    myQuery = {"city": loc}
   
    display_data = {
        "username": 0,
        "password": 0,
        "role": 0,
    }
    places_data = []
    for locs in users.find(myQuery, display_data):
        places_data.append(locs)
        
    if places_data != ' ':    
        return jsonify(places_data)

    else:
        return jsonify({"message": "no places to visit at this location :("})


# ---------------------------------------------------///////       Route to get images      ///////////-------------------------------------------------


@app.route("/getimage/<path:id>",methods = ['GET'])
def get_image(id):

    img = f"{id}.jpg"
    try:
        return redirect(url_for('static', filename='images/' + img), code=301)
    except FileNotFoundError:
        abort(404)


# -----------------------------///////////////////              route to post reviews               //////////////----------------------------------------


@app.route("/post_reviews",methods = ['POST'])
@token_verify
def post_reviews(current_user):

    user = users.find_one({"_id": current_user["_id"]})
    business_id = request.args["business_id"]
    business = users.find_one({"_id": business_id})
    
    query = {
        "user_id": user['_id'],
        "business_id": business_id,
    }

    if Rdata.find_one(query):
        return jsonify({"message": "Cannot review same place multiple times"})

    status1 = Rdata.insert({
        "_id": str(uuid.uuid4()),
        "user_id": user['_id'],
        "business_id": business_id,
        "business_name": business["name"],
        "business_username": business["username"],
        "business_img": business["image"],
        "name": user['name'],
        "username": user['username'],
        "review": request.args["review"],
        "ratings": float(request.args["ratings"]),
    })

    reviews_data = Rdata.find({"business_id": business_id})
    lst = []
    for i in reviews_data:
        lst.append(i["ratings"])

    status2 = avg_ratings(lst, business_id)

    if status1 and status2:
        return jsonify({'message':"Review registered successfully"})

    return jsonify({"message":'please try again'})


# ---------------------------------------------------///////       Route to get reviews      ///////////-------------------------------------------------


@app.route("/get_reviews/<path:id>",methods = ['GET'])
def get_reviews(id):
    myQuery = {}
    rws = []

    user = Rdata.find_one({'user_id': id})
    business = Rdata.find_one({'business_id': id}) 

    if user != None and user['user_id'] == id:
        myQuery = {"user_id": id}

    elif business != None and business['business_id'] == id:
        myQuery = {"business_id": id}

    else:
        return jsonify({
            "message": "no reviews yet :(",
            "reviews": rws
        })

    for locs in Rdata.find(myQuery):
        rws.append(locs)

    
    if rws != ' ':
        return jsonify({
            "message": "here are some reviews",
            "reviews": rws
        })

    else:
        return jsonify({
            "message": "no reviews yet :(",
            "reviews": rws
        })

# ---------------------------------------------------///////       Route to update reviews      ///////////-------------------------------------------------


@app.route("/update_review",methods = ['PUT'])
@token_verify
def update_reviews(current_user):
    user = users.find_one({"_id": current_user["_id"]})

    myQuery = {"user_id": user['_id']}

    get_new_data =  request.get_json()
    new_data = {"$set":{}}

    for key in get_new_data:
        new_data["$set"][key] = get_new_data[key]

    
    status = Rdata.update_one(myQuery, new_data)
    if status:
        return jsonify({'message': "updated successfully"})

    return jsonify({"message":"request cannot be processed, please try again!!"})


# ---------------------------------------------------///////       Route to delete reviews      ///////////-------------------------------------------------


@app.route('/delete_review', methods = ['DELETE'])
@token_verify
def delete_review(current_user):
    user = users.find_one({"_id": current_user["_id"]})

    myQuery = {"_id": user['_id']}
    status = Rdata.delete_one(myQuery)

    if status:
        return jsonify({'message': "Review deleted successfully"})

    return jsonify({"message":"request cannot be processed, please try again!!"})


# ---------------------------------------------------///////       Main function to run the flask app      ///////////-------------------------------------------------


if __name__ == "__main__":
    app.run(debug=True)
