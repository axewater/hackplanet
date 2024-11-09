from modules import create_app, db
from modules.models import FlagsObtained, ChallengesObtained, SystemMessage, User, Flag, Challenge
from datetime import datetime

def generate_historical_messages(dry_run=True):
    """
    Generate system messages for existing flag and challenge achievements.
    
    Args:
        dry_run (bool): If True, only simulate the changes without saving to database
    """
    print("Starting historical message generation...")
    app = create_app()
    
    with app.app_context():
        # Track statistics
        messages_created = 0
        errors = 0
        
        # Process flag achievements
        print("Processing flag achievements...")
        flag_achievements = FlagsObtained.query.all()
        for achievement in flag_achievements:
            try:
                # Get related data
                user = User.query.get(achievement.user_id)
                flag = Flag.query.get(achievement.flag_id)
                host = flag.host
                
                if not all([user, flag, host]):
                    print(f"Missing related data for flag achievement ID: {achievement.id}")
                    errors += 1
                    continue
                
                # Create message content
                message_content = f"User {user.name} obtained {flag.type} flag on host {host.name}"
                
                if not dry_run:
                    # Create and save the system message
                    system_message = SystemMessage(type='flag_win', contents=message_content)
                    system_message.created_at = achievement.created_at if hasattr(achievement, 'created_at') else datetime.utcnow()
                    
                    # Mark as read for all users
                    all_users = User.query.all()
                    for u in all_users:
                        system_message.mark_as_read(u)
                    
                    db.session.add(system_message)
                    db.session.commit()
                
                messages_created += 1
                if messages_created % 100 == 0:
                    print(f"Processed {messages_created} messages...")
                
            except Exception as e:
                print(f"Error processing flag achievement ID {achievement.id}: {str(e)}")
                errors += 1
                if not dry_run:
                    db.session.rollback()
        
        # Process challenge achievements
        print("\nProcessing challenge achievements...")
        challenge_achievements = ChallengesObtained.query.filter_by(completed=True).all()
        for achievement in challenge_achievements:
            try:
                # Get related data
                user = User.query.get(achievement.user_id)
                challenge = Challenge.query.get(achievement.challenge_id)
                
                if not all([user, challenge]):
                    print(f"Missing related data for challenge achievement ID: {achievement.id}")
                    errors += 1
                    continue
                
                # Create message content
                message_content = f"User {user.name} completed challenge {challenge.name}"
                
                if not dry_run:
                    # Create and save the system message
                    system_message = SystemMessage(type='challenge_win', contents=message_content)
                    system_message.created_at = achievement.completed_at or datetime.utcnow()
                    
                    # Mark as read for all users
                    all_users = User.query.all()
                    for u in all_users:
                        system_message.mark_as_read(u)
                    
                    db.session.add(system_message)
                    db.session.commit()
                
                messages_created += 1
                if messages_created % 100 == 0:
                    print(f"Processed {messages_created} messages...")
                
            except Exception as e:
                print(f"Error processing challenge achievement ID {achievement.id}: {str(e)}")
                errors += 1
                if not dry_run:
                    db.session.rollback()
        
        # Print summary
        print("\nProcess completed!")
        print(f"Messages that would be created: {messages_created}")
        print(f"Errors encountered: {errors}")
        if dry_run:
            print("\nThis was a dry run. No changes were made to the database.")
            print("Run with dry_run=False to apply changes.")

if __name__ == "__main__":
    # First do a dry run
    print("Performing dry run...\n")
    generate_historical_messages(dry_run=True)
    
    # Ask for confirmation before real run
    response = input("\nWould you like to proceed with the actual message generation? (y/N): ")
    if response.lower() == 'y':
        print("\nProceeding with actual message generation...\n")
        generate_historical_messages(dry_run=False)
    else:
        print("\nOperation cancelled.")
