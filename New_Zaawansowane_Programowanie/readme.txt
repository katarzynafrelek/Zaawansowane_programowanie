Requirements:
1. Docker desktop
2. Heroku CLI

Installation
1. Change directory to project dir
2. Execute following commands in order:
heroku login
heroku container:login
heroku create <heroku_app_name>
heroku container:push web --app <heroku_app_name>
heroku container:release web --app <heroku_app_name>