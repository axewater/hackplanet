# /app.py
from modules import create_app
from modules.database_manager import DatabaseManager

app = create_app()

if __name__ == '__main__':
    # Ensure the database schema is up to date
    db_manager = DatabaseManager()
    db_manager.add_purchase_url_column_if_not_exists()
    db_manager.add_used_by_column_to_invite_tokens()
    db_manager.add_solution_column_if_not_exists()
    db_manager.add_theme_column_to_user_preferences()
    
    app.run(host="0.0.0.0", debug=True, port=5003)
