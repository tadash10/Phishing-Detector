from flask import Blueprint, render_template

handle_errors = Blueprint('errors', __name__)

@handle_errors.app_errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@handle_errors.app_errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500
