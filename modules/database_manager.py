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
    
    def add_theme_column_to_user_preferences(self):
        add_column_sql = """
        ALTER TABLE user_preferences
        ADD COLUMN IF NOT EXISTS theme VARCHAR(50) DEFAULT 'default';
        """
        print("Adding 'theme' column to user_preferences table")
        try:
            with self.engine.connect() as connection:
                connection.execute(text(add_column_sql))
                connection.commit()
            print("Column 'theme' successfully added to the 'user_preferences' table.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.engine.dispose()

    def add_muted_column_to_message_read_status(self):
        add_column_sql = """
        ALTER TABLE message_read_status
        ADD COLUMN IF NOT EXISTS muted BOOLEAN DEFAULT FALSE;
        """
        print("Adding 'muted' column to message_read_status table")
        try:
            with self.engine.connect() as connection:
                connection.execute(text(add_column_sql))
                connection.commit()
            print("Column 'muted' successfully added to the 'message_read_status' table.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.engine.dispose()

    def add_enable_information_messages_column(self):
        add_column_sql = """
        ALTER TABLE rss_config
        ADD COLUMN IF NOT EXISTS enable_information_messages BOOLEAN DEFAULT TRUE;
        """
        print("Adding 'enable_information_messages' column to rss_config table")
        try:
            with self.engine.connect() as connection:
                connection.execute(text(add_column_sql))
                connection.commit()
            print("Column 'enable_information_messages' successfully added to the 'rss_config' table.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.engine.dispose()

    def create_profile_backgrounds_table(self):
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS profile_backgrounds (
            id SERIAL PRIMARY KEY,
            filename VARCHAR(256) NOT NULL UNIQUE,
            display_name VARCHAR(128),
            enabled BOOLEAN DEFAULT TRUE,
            date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            "order" INTEGER DEFAULT 0
        );
        """
        print("Creating profile_backgrounds table if it doesn't exist")
        try:
            with self.engine.connect() as connection:
                connection.execute(text(create_table_sql))
                connection.commit()
            print("Table 'profile_backgrounds' successfully created.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.engine.dispose()

    def add_background_id_to_user_preferences(self):
        add_column_sql = [
            """ALTER TABLE user_preferences 
               ADD COLUMN IF NOT EXISTS background_id INTEGER REFERENCES profile_backgrounds(id);""",
            """ALTER TABLE user_preferences 
               ADD COLUMN IF NOT EXISTS auto_read_leaderboard BOOLEAN DEFAULT FALSE;""",
            """ALTER TABLE user_preferences 
               ADD COLUMN IF NOT EXISTS auto_read_wins BOOLEAN DEFAULT FALSE;""",
            """ALTER TABLE user_preferences 
               ADD COLUMN IF NOT EXISTS auto_read_information BOOLEAN DEFAULT FALSE;"""
        ]
        print("Adding background_id and message preferences columns to user_preferences table")
        try:
            with self.engine.connect() as connection:
                # Execute each SQL statement separately
                for sql in add_column_sql:
                    connection.execute(text(sql))
                connection.commit()
            print("Columns successfully added to the 'user_preferences' table.")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            self.engine.dispose()
