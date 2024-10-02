# Project Summary

## Overview of Languages, Frameworks, and Main Libraries Used
- **Languages:** Python
- **Frameworks:** Flask
- **Main Libraries:** SQLAlchemy, Flask-Mail, Flask-WTF, Werkzeug, APScheduler, WTForms, psycopg2-binary, azure-identity, azure-mgmt-compute

## Purpose of the Project
The project, titled HackPlanet.EU, is an innovative Capture The Flag (CTF) platform designed to motivate employees to learn about ethical hacking. It provides various features such as Hacking Labs, Challenges, Study Rooms, Quizzes, Leaderboard, User Progress Tracking, and an Admin Panel. The platform aims to enhance cybersecurity skills within organizations through gamification, diverse learning paths, hands-on experience, progress tracking, continuous learning, team building, and recognition.

## Relevant Files for Configuration and Building
1. **Dockerfile:** `/Dockerfile`
2. **Config File:** `/config.py`
3. **Requirements File:** `/requirements.txt`
4. **App Entry Point:** `/app.py`
5. **Docker Compose Configuration:** `/docker-compose.yml`
6. **Entrypoint Script:** `/entrypoint.sh`
7. **Database Management Script:** `/manage_db.py`
8. **Setup Script (No SMTP):** `/setup_nosmtp.py`

## Source Files Directory
- Source files are located in the `/modules` directory, which contains Python modules for various functionalities like Azure utilities, database management, forms, models, and routes.

## Documentation Files Location
- Documentation files are located in the `/` directory and are contained within the `README.md` file. The README provides an overview of the platform's features, how to leverage it for employee motivation, and instructions for getting started with HackPlanet.EU.

This project utilizes Flask as the main framework for building the CTF platform, with various libraries for database management, email handling, form validation, scheduling, and Azure integration. The configuration files, build scripts, and source code files are organized in a structured manner to facilitate the setup and deployment of the HackPlanet.EU platform.