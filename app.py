from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# In-memory "database" (dictionary) to store users and their hashed passwords
users_db = {}


# POST /sethash - Set a hashed password for a user
@app.route('/sethash', methods=['POST'])
def set_hash():
    # Get the JSON data from the request body
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the username already exists
    if username in users_db:
        return jsonify({'message': 'Username already exists'}), 400

    # Hash the password using Werkzeug's generate_password_hash method
    hashed_password = generate_password_hash(password)

    # Store the hashed password in the dictionary (acting as a database)
    users_db[username] = hashed_password

    return jsonify({'message': 'User registered successfully'}), 201


# GET /gethash - Get the hashed password for a user
@app.route('/gethash', methods=['GET'])
def get_hash():
    # Get the username from the request arguments
    username = request.args.get('username')

    # If the username doesn't exist, return an error
    if username not in users_db:
        return jsonify({'message': 'User not found'}), 404

    # Retrieve the hashed password
    hashed_password = users_db[username]

    return jsonify({'username': username, 'hashed_password': hashed_password})


# GET /login - Login attempt by verifying the hashed password
@app.route('/login', methods=['GET'])
def login():
    username = request.args.get('username')
    password = request.args.get('password')

    # Check if the username exists in our "database"
    if username not in users_db:
        return jsonify({'message': 'User not found'}), 404

    # Retrieve the stored hashed password
    stored_hashed_password = users_db[username]

    # Use Werkzeug's check_password_hash to verify the entered password
    if check_password_hash(stored_hashed_password, password):
        return jsonify({'message': f'Welcome back, {username}! Login successful.'})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401


# GET /register - Endpoint to show how to register a user
@app.route('/register', methods=['GET'])
def register():
    return """
        To register, use POST /sethash with a JSON body:
        {
            "username": "your_username",
            "password": "your_password"
        }
    """


# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
