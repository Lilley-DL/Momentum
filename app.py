from flask import Flask,render_template,url_for,request,jsonify,redirect,flash

from flask_wtf import FlaskForm
from wtforms import StringField,EmailField,SubmitField,PasswordField
from wtforms.validators import DataRequired,Email
import flask_login
from dotenv import load_dotenv
import csv , json, os, hashlib, binascii

from bleach import clean

from Database import get_db_connection,Database

from supabase import create_client


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY')

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

db = None

#database thingssssss
#should allow for development using a dev database
if app.debug:
    DATABASE_URL = os.environ.get('DEV_DATABASE_URL')
    #database object instance 
    db = Database(DATABASE_URL)
else:
    #use supabase here ?
    DATABASE_URL = os.environ.get('DATABASE_URL')



class SignupForm(FlaskForm):
    username = StringField('Username: ',validators=[DataRequired()])
    email = EmailField('Email: ',validators=[DataRequired()])
    password = PasswordField('Password: ',validators=[DataRequired()])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
    username = StringField('Username: ',validators=[DataRequired()])
    email = EmailField('Email: ',validators=[DataRequired()])
    password = PasswordField('Password: ',validators=[DataRequired()])
    submit = SubmitField("Submit")

supabase = create_client(os.environ.get('SUPA_PROJECT_URL'),os.environ.get('SUPA_API_KEY'))

##USER MANAGEMENT

class CustomAnonymousUser(flask_login.AnonymousUserMixin):
    def __init__(self):
        self.id = None
        self.username = "Guest"
        self.email = None

login_manager.anonymous_user = CustomAnonymousUser


class User(flask_login.UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader ##this is the one gemini created after i started using supabase auth instead of the og table for auth 
def load_user(user_id):
    try:
        response = supabase.auth.get_user()
        user_data = response.user
        app.logger.info(f"USER INFO FOR LOAD _USER {user_data}")
        if user_data:
            user_id = user_data.id
            username = user_data.email
            email = user_data.email
        
        # Create the User object
        current_user = User(user_id, username, email)
        return current_user
    except Exception as e:
        app.logger.info(f" -->> USER LOADER EXCEPTION :: {e}")
        return None


#                               ROUTES 
@app.route("/")
def index():
    return render_template("index.html")

##signup route 

@app.route('/signup',methods=['GET','POST'])
def signup():
    #this is where a class would be useful lol 
    username = None
    email = None
    password = None
    form = SignupForm()
    
    if request.method == 'GET':
        #look for error messag in the url 
        # form = SignupForm()
        errors = request.args.get('errors')
        return render_template("signup.html",username=username,email=email,password=password,form=form,errors=errors)
    
    if form.validate_on_submit():
        app.logger.info(f" AFTER VALID SUBMIT :: {form}")
        username = form.username.data
        form.username.data = ''

        email = form.email.data
        form.email.data = ''

        password = form.password.data # might need to hash it here
        form.password.data = ''

        try:
            # Check for existing user
            response = supabase.table('users').select('user_id').eq('email',email).execute()
            user_exists = len(response.data) > 0

            if not user_exists:
                # No existing user, register new user
                hashed_password = supabase.auth.sign_up({"email":email,"password":password})
                return redirect('/login')
            else:
                # User already exists, display error
                # return render_template('signup.html', errors="Email already in use")
                flash("email was elrady in use")
                return redirect("/signup")
        except Exception as e:
            # Handle potential errors during Supabase interaction
            print(f"Error during signup: {e}")
            # return render_template('signup.html', errors="An error occurred. Please try again.")
            flash(e)
            return redirect("/signup")

    #return render_template('signup.html')

##LOGIN

@app.route('/login',methods=['GET','POST'])
def login():
    username = None
    email = None
    password = None

    form = LoginForm()

    if form.validate_on_submit(): ##POST
        username = form.username.data
        form.username.data = ''

        email = form.email.data
        form.email.data = ''

        password = form.password.data # might need to hash it here
        form.password.data = ''

        try:
            sign_in = supabase.auth.sign_in_with_password({"email": email, "password": password})
            user_data = sign_in.user
            app.logger.info(f"USER INFO FOR LOGIN {user_data}")
            if user_data:
                user_id = user_data.id
                username = user_data.email
                email = user_data.email
        
        # Create the User object
                current_user = User(user_id, username, email)
                flask_login.login_user(current_user)
                return redirect('/profile')
            else:
                flash("User login failed")
                return render_template('login.html', error='Invalid credentials',form=form)

        except Exception as e:
            # Handle errors, e.g., incorrect credentials
            flash(e)
            return render_template('login.html', error='Invalid credentials',form=form)
    
    if request.method == 'GET':
        #look for error messag in the url 
        errors = request.args.get('errors')
        return render_template("login.html",form=form,errors=errors)


#add login required decorator 
@app.route("/profile",methods=['GET','POST'])
@flask_login.login_required
def profile():
    current_user = flask_login.current_user  # Automatically set by Flask-Login

    # Safely handle the user object
    if not current_user.is_authenticated:
        app.logger.info("User is not authenticated. Redirecting to login.")
        return redirect('/login')  # Redirect unauthenticated users
    
    #get the entries for this user 
    
    response = supabase.table("entry").select("*").eq("user_id", current_user.id).execute()
    r2 = supabase.table("accumulated_calories_for_user").select("*").execute()
    totalCalories = r2.data

    entries = response.data if response.data else []
    app.logger.info(f"SUPA RETREIVED {entries}")

    # Render profile page for authenticated users
    return render_template("profile.html", user=current_user, entries=entries,totalCals = totalCalories)

@app.route("/createEntry",methods=['GET','POST'])
@flask_login.login_required
def createEntry():
    app.logger.info(f"User is authenticated: {flask_login.current_user.is_authenticated}")
    if request.method == "POST":

        app.logger.info(f"REQUEST FORM DATA {request.form}")
        entryName =  clean(request.form.get('entryName'))
        #validate and ecape the name 

        macros = {
            "calories":None,
            "protein":None,
            "fats":None,
            "carbs":None,
            "fibre":None
        }
                #macro info
        calories = float(request.form.get('calories'))
        protein = float(request.form.get('protein'))
        fats = float(request.form.get('fats'))
        carbs = float(request.form.get('carbs'))
        fibre = float(request.form.get('fibre'))

        #sanitize and check for negative values 
        
        macros["calories"] = calories
        macros["protein"] = protein
        macros['fats'] = fats
        macros['carbs'] = carbs
        macros['fibre'] = fibre

        data = {
            "entry_data":macros,
            "entry_name":entryName,
        }

        try:
            response = supabase.table("entry").insert(data).execute()
            app.logger.info(f"RESPONSE FROM SUPA INSERT = {response}")
        except Exception as e:
            app.logger.info(f"RESPONSE FROM SUPA error = {e}")
            flash(f"something went wrong :: {e}")
            return redirect(url_for("createEntry"))

        return redirect(url_for("createEntry"))

    return render_template("createEntry.html")


@app.route("/logout")
def logout():
    response = supabase.auth.sign_out()
    flask_login.logout_user()
    flash(f"Logged out succesfully")
    return redirect(url_for('index'))

@login_manager.unauthorized_handler
def unauthorized_handler():
    #return "Unauthorized", 401
    flash("Please login")
    return redirect(url_for('login'))


##for render to run 
if __name__ == "__main__":
    app.run()
    