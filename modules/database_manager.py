import os
from sqlalchemy import create_engine, text
from config import Config

class DatabaseManager:
    def __init__(self):
        # Load the database configuration from Config
        self.database_uri = Config.SQLALCHEMY_DATABASE_URI
        # Create a SQLAlchemy engine
        self.engine = create_engine(self.database_uri)

    def add_purchase_url_column_if_not_exists(self):
        # SQL command to add a new column
        add_column_sql = """
        ALTER TABLE courses
        ADD COLUMN IF NOT EXISTS purchase_url VARCHAR(512);
        """
        print("Upgrading database to the latest schema")
        try:
            # Execute the SQL command
            with self.engine.connect() as connection:
                connection.execute(text(add_column_sql))
                connection.commit()
            print("Column 'purchase_url' successfully added to the 'courses' table.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            # Close the database connection
            self.engine.dispose()

    def add_solution_column_if_not_exists(self):
        # SQL command to add a new column
        add_column_sql = """
        ALTER TABLE challenges
        ADD COLUMN IF NOT EXISTS solution TEXT;
        """
        print("Adding 'solution' column to challenges table")
        try:
            with self.engine.connect() as connection:
                connection.execute(text(add_column_sql))
                connection.commit()
            print("Column 'solution' successfully added to the 'challenges' table.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.engine.dispose()




    def add_used_by_column_to_invite_tokens(self):
        add_column_sql = """
        ALTER TABLE invite_tokens
        ADD COLUMN IF NOT EXISTS used_by VARCHAR(36) REFERENCES users(user_id);
        """
        print("Adding 'used_by' column to invite_tokens table")
        try:
            with self.engine.connect() as connection:
                connection.execute(text(add_column_sql))
                connection.commit()
            print("Column 'used_by' successfully added to the 'invite_tokens' table.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.engine.dispose()
