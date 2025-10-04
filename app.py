from flask import Flask, request, jsonify
import warnings
import traceback

# --- 1. Import your core inference function ---
# We are importing the function from the 'inference.py' file you just created.
# This keeps our API code clean and separate from the model logic.
try:
    from inference import predict_threat
except ImportError:
    print("FATAL ERROR: Could not import 'predict_threat' from 'inference.py'.")
    print("Please ensure 'inference.py' is in the same directory as 'app.py'.")
    exit()

warnings.filterwarnings('ignore')

# --- 2. Initialize the Flask Application ---
# This creates the web server.
app = Flask(__name__)
print("Flask application initialized.")


# --- 3. Define the API Endpoint ---
@app.route('/predict', methods=['POST'])
def handle_prediction():
    """
    This function is the core of the API. It listens for POST requests on the /predict URL.
    It expects a JSON payload with the raw request data.
    """
    print("\nReceived a new request on /predict endpoint...")

    # --- Input Validation ---
    if not request.is_json:
        print("Error: Request is not in JSON format.")
        return jsonify({"error": "Invalid input: request must be in JSON format."}), 400

    data = request.get_json()
    print(f"Request data: {data}")

    # Check for required fields
    required_fields = ['IP', 'Endpoint', 'User-Agent', 'Country', 'Date']
    missing_fields = [field for field in required_fields if field not in data]
    if missing_fields:
        error_msg = f"Missing required fields: {', '.join(missing_fields)}"
        print(f"Error: {error_msg}")
        return jsonify({"error": error_msg}), 400

    # --- Call the Model ---
    try:
        # Pass the validated JSON data directly to your prediction function
        result = predict_threat(data)
        
        # Return the prediction as a JSON response
        print("Successfully returned prediction.")
        return jsonify(result), 200

    except Exception as e:
        # A robust error handler for any unexpected issues during prediction
        error_details = traceback.format_exc()
        print(f"FATAL ERROR during prediction: {e}")
        print(f"Details: {error_details}")
        return jsonify({
            "error": "An internal error occurred during prediction.",
            "details": str(e)
        }), 500


# A simple root endpoint to confirm the API is running
@app.route('/')
def index():
    return "<h1>Cybersecurity Threat Detection API</h1><p>Send a POST request to /predict to use the model.</p>"


# --- 4. Run the Application ---
if __name__ == '__main__':
    # This makes the server accessible from other devices on your network.
    # The default port is 5000.
    app.run(host='0.0.0.0', port=5000, debug=False)
