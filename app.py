from flask import Flask, request, jsonify, render_template
from bson.json_util import dumps
from datetime import datetime, timezone
import json
import pymongo
from datetime import datetime
import os
from dotenv import load_dotenv
import hashlib
import hmac

# Load environment variables
load_dotenv()

app = Flask(__name__)

# MongoDB connection
MONGODB_URI = os.getenv('MONGODB_URI')
if not MONGODB_URI:
    raise ValueError("MONGODB_URI environment variable is required")

client = pymongo.MongoClient(MONGODB_URI)
db = client.webhook_db
collection = db.github_events

# GitHub webhook secret (for security)
GITHUB_WEBHOOK_SECRET = os.getenv('GITHUB_WEBHOOK_SECRET', '')

def verify_signature(payload_body, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256 signature."""
    if not signature_header:
        return False
    
    hash_object = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode('utf-8'),
        msg=payload_body,
        digestmod=hashlib.sha256
    )
    expected_signature = "sha256=" + hash_object.hexdigest()
    return hmac.compare_digest(expected_signature, signature_header)

@app.route('/')
def index():
    """Render the main page that displays GitHub events."""
    return render_template('index.html')


@app.route('/api/events')
def get_events():
    """API endpoint to get the latest GitHub events."""
    try:
        # Get latest 50 events
        events_cursor = collection.find().sort('timestamp', -1).limit(50)
        events = list(events_cursor)

        # Convert ObjectId and datetime to JSON serializable format
        for event in events:
            event['_id'] = str(event['_id'])
            if 'timestamp' in event:
                event['timestamp'] = event['timestamp'].isoformat()  # Convert datetime to ISO string

        return jsonify(events)
    except Exception as e:
        print("Error in /api/events:", e)
        return jsonify({'error': str(e)}), 500


@app.route('/webhook', methods=['POST'])
def webhook():
    """Handle GitHub webhook events."""
    try:
        # Get the request data
        payload = request.get_json()
        
        # Verify the signature (optional but recommended for security)
        signature = request.headers.get('X-Hub-Signature-256')
        if GITHUB_WEBHOOK_SECRET and not verify_signature(request.data, signature):
            return jsonify({'error': 'Invalid signature'}), 401
        
        # Process the webhook based on the event type
        event_type = request.headers.get('X-GitHub-Event')
        
        if event_type == 'push':
            handle_push_event(payload)
        elif event_type == 'pull_request':
            handle_pull_request_event(payload)
        else:
            print(f"Unhandled event type: {event_type}")
            return jsonify({'message': 'Event type not handled'}), 200
        
        return jsonify({'message': 'Webhook received successfully'}), 200
        
    except Exception as e:
        print(f"Error processing webhook: {str(e)}")
        return jsonify({'error': str(e)}), 500

def handle_push_event(payload):
    """Handle push events."""
    try:
        # Extract relevant information
        author = payload['pusher']['name']
        branch = payload['ref'].split('/')[-1]  # Extract branch name from refs/heads/branch_name
        timestamp = datetime.now(timezone.utc)
        repository = payload['repository']['name']
        
        # Create document for MongoDB
        document = {
            'action': 'push',
            'author': author,
            'to_branch': branch,
            'from_branch': None,
            'repository': repository,
            'timestamp': timestamp,
            'raw_payload': payload
        }
        
        # Insert into MongoDB
        collection.insert_one(document)
        print(f"Push event saved: {author} pushed to {branch}")
        
    except Exception as e:
        print(f"Error handling push event: {str(e)}")
        raise

def handle_pull_request_event(payload):
    """Handle pull request events."""
    try:
        # Only process opened and closed (merged) pull requests
        action = payload['action']
        
        if action == 'opened':
            # Extract relevant information
            author = payload['pull_request']['user']['login']
            from_branch = payload['pull_request']['head']['ref']
            to_branch = payload['pull_request']['base']['ref']
            timestamp = datetime.now(timezone.utc)
            repository = payload['repository']['name']
            
            # Create document for MongoDB
            document = {
                'action': 'pull_request',
                'author': author,
                'from_branch': from_branch,
                'to_branch': to_branch,
                'repository': repository,
                'timestamp': timestamp,
                'raw_payload': payload
            }
            
            # Insert into MongoDB
            collection.insert_one(document)
            print(f"Pull request event saved: {author} submitted PR from {from_branch} to {to_branch}")
            
        elif action == 'closed' and payload['pull_request']['merged']:
            # This is a merge event
            author = payload['pull_request']['merged_by']['login']
            from_branch = payload['pull_request']['head']['ref']
            to_branch = payload['pull_request']['base']['ref']
            timestamp = datetime.now(timezone.utc)
            repository = payload['repository']['name']
            
            # Create document for MongoDB
            document = {
                'action': 'merge',
                'author': author,
                'from_branch': from_branch,
                'to_branch': to_branch,
                'repository': repository,
                'timestamp': timestamp,
                'raw_payload': payload
            }
            
            # Insert into MongoDB
            collection.insert_one(document)
            print(f"Merge event saved: {author} merged {from_branch} to {to_branch}")
            
    except Exception as e:
        print(f"Error handling pull request event: {str(e)}")
        raise

if __name__ == '__main__':
    import os
    port = int(os.environ.get("PORT", 10000))
    app.run(host='0.0.0.0', port=port)
