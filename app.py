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

class Workout:
    def __init__(self,data):
        self.dateTime = data['date']
        # self.workout_data = json.loads(data['workout_json'])
        self.workout_data = data['workout_json']
        
        self.sets = self.workout_data['sets']

        self.zippedSets = list(zip(self.workout_data['movements'],self.workout_data['sets']))

    def __str__(self):
        return json.dumps(self.workout_data)

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
    email = EmailField('Email: ',validators=[DataRequired()])
    password = PasswordField('Password: ',validators=[DataRequired()])
    submit = SubmitField("Submit")

class LoginForm(FlaskForm):
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
        #app.logger.info(f"USER INFO FOR LOAD _USER {user_data}")
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

        email = form.email.data
        form.email.data = ''

        password = form.password.data # might need to hash it here
        form.password.data = ''

        try:
            app.logger.info("Am i here ?")
            response = supabase.auth.sign_up({"email":email,"password":password})
            return redirect('/login')
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
    email = None
    password = None

    form = LoginForm()

    if form.validate_on_submit(): ##POST
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
    try:
        macroResponse = supabase.table("macro_entry").select("*").eq("user_id", current_user.id).execute()
  
        macroEntries = macroResponse.data if macroResponse.data else []
        
        workoutResponse = supabase.table("workout_for_user_by_date").select("*").execute()
        app.logger.info(f" WORKOUT RESPONSE :: {workoutResponse.data}")

        workoutObjects = []
        for w in workoutResponse.data:
            # app.logger.info(f" WORKOUT OBJECT :: {w['workout_json']}")
            wobject = Workout(w)
            app.logger.info(f" WORKOUT OBJECT :: {wobject}")
            workoutObjects.append(wobject)

        #app.logger.info(f" WORKOUT OBJECTS :: {workoutObjects}")

        # Render profile page for authenticated users
        return render_template("profile.html", user=current_user, entries=macroEntries, workoutObjects = workoutObjects)
    except Exception as e:
        flash(e)
        return render_template("profile.html", user=current_user)

@app.route("/view/meals")
@flask_login.login_required
def viewMeals():
    current_user = flask_login.current_user  # Automatically set by Flask-Login

    # Safely handle the user object
    if not current_user.is_authenticated:
        app.logger.info("User is not authenticated. Redirecting to login.")
        return redirect('/login')  # Redirect unauthenticated users
    
    try:
        macroResponse = supabase.table("macro_entry").select("*").eq("user_id", current_user.id).execute()
        macroEntries = macroResponse.data if macroResponse.data else []
        return render_template("viewMeals.html",entries=macroEntries)
    except Exception as e:
        flash(e)
        return render_template("viewMeals.html")


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
            "user_id": flask_login.current_user.id
        }

        try:
            response = supabase.table("macro_entry").insert(data).execute()
            app.logger.info(f"RESPONSE FROM SUPA INSERT = {response}")
        except Exception as e:
            app.logger.info(f"RESPONSE FROM SUPA error = {e}")
            flash(f"something went wrong :: {e}")
            return redirect(url_for("createEntry"))

        return redirect(url_for("createEntry"))

    return render_template("createEntry.html")

@app.route("/add-workout",methods=['GET','POST'])
@flask_login.login_required
def addWorkout():

    if flask_login.current_user.is_authenticated: #probably dont need this 
        workoutObject = {}
        movementsObject = {}

        if request.method == 'POST':
            #get ther form values 
            #DONT FORGET the reps&sets and rthe movements will be lists 
            movements = request.form.getlist("movement")
            reps = request.form.getlist("reps")

            cleanMovements = []
            cleanReps = []

            for mov in movements:
                app.logger.info(f"UNCLEAN :: {mov}")
                app.logger.info(f"CLEAN :: {clean(mov)}")
                cleanMovements.append(clean(mov))
            

            workoutObject['name'] = clean(request.form.get("workout-name"))
            workoutObject['date'] = request.form.get("date")
            workoutObject['weight_format'] = request.form.get("weight-format")
            # workoutObject['movements'] = movements
            workoutObject['movements'] = cleanMovements
            workoutObject['sets'] = []
            workoutObject['category'] = request.form.get("category")
            workoutObject['effort'] = request.form.get("effort")

            #split the string on the underscore to get the movement and the reps and weight ? 
            #check movements length 
            for m in movements:

                cleanWeights = []
                cleanReps = []
                weights = request.form.getlist(m+"_weight")
                reps = request.form.getlist(m+"_reps")

                for w in weights:
                    cleanWeights.append(clean(w))
                
                for r in reps:
                    cleanReps.append(clean(r))

                # combined = list(zip(weights,reps))
                combined = list(zip(cleanWeights,cleanReps))

                movementsObject['movement'] = clean(m)
                movementsObject['sets'] = combined

                c2 = [combined]
                
                # workoutObject['movements'] += c2
                # workoutObject['movements'] += m
                workoutObject['sets'] += c2

            data = json.dumps(workoutObject)
            app.logger.info(f" WORKOUT :: {data}")

            supaData = {
                "workout_json":workoutObject,
                "user_id": flask_login.current_user.id
            }

            try:
                response = supabase.table("workout").insert(supaData).execute()
                app.logger.info(f"Workout added sucesfully :: ")
                return redirect(url_for('addWorkout'))
            except Exception as e:
                app.logger.info(f"SOMETHING WENT WRONG ADDING WORKOUT :: {e}")

                flash(f"Something went wrong {e}")
                return redirect(url_for('addWorkout'))

        else:
            return render_template("addWorkout.html")

    if request.method == 'GET':
        return render_template("addWorkout.html")

##EMAIL STUFF
@app.route("/confirm",methods=['GET'])
def confirmEmail():
    
    token = request.args.get('access_token')
    tokenType = request.args.get('type')

    app.logger.info(f"User confirm token :: {token}")
    app.logger.info(f"REQUEST ARGS:: {request.args}")

    form = LoginForm()

    #check validity 
    if tokenType == 'signup' and token:
        try:
            response = supabase.auth.get_user(token)
            
            if response is not None:
                # Verification successful, redirect to a welcome page or login page
                flash("Email Confirmed Succesfully ")
                return redirect(url_for('login'))
            else:
                # Handle error, e.g., display an error message
                flash('Invalid verification link')
                return redirect(url_for('login'))
                #return render_template('login.html',form=form)
        except Exception as e:
        # Handle unexpected errors
            flash(f"Something went wrong {e}")
            return render_template('login.html',form=form)
    else:
        flash("Something went wrong again")
        return render_template("confirm.html")

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
    