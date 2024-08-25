from flask import Flask
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

def create_app():
    app = Flask(__name__)
    
    # Load configuration from a config file
    app.config.from_object('app.config.Config')
    
    # Initialize Cache
    cache = Cache(app)
    
    # Initialize Rate Limiter
    limiter = Limiter(app, key_func=get_remote_address)

    # Register blueprints (routes)
    from app.routes import main
    app.register_blueprint(main)
    
    # Error handlers
    from app.errors import handle_errors
    app.register_blueprint(handle_errors)

    return app

# Initialize logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')
