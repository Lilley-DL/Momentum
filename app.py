from flask import Flask,render_template,url_for,request,jsonify,redirect,flash,session

from flask_wtf import FlaskForm
from wtforms import StringField,EmailField,SubmitField,PasswordField,HiddenField
from wtforms.validators import DataRequired,Email
import flask_login
from dotenv import load_dotenv
import csv , json, os, hashlib, binascii
from datetime import datetime

from bleach import clean

#from Database import get_db_connection,Database

from supabase import create_client


def format_date(date_string):
    """Formats a date string to a more readable format."""
    try:
        dt_object = datetime.strptime(date_string, '%Y-%m-%dT%H:%M:%S.%f')
        return dt_object.strftime('%B %d, %Y %I:%M %p')
    except ValueError:
        # Handle cases where the date string is invalid
        return "Invalid Date"


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('CSRF_SECRET_KEY')

login_manager = flask_login.LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

db = None

class Workout:
    def __init__(self,data):
        self.workout_id = data['id']
        self.workout_data = data['workout_json']
        self.name = self.workout_data['name']

        if 'date' in data:
            self.dateTime = datetime.fromisoformat(data['date'])
        else:
            self.dateTime = datetime.fromisoformat(self.workout_data['date'])

        if 'type' in self.workout_data: #no type attribute means its legacy ?

            if self.workout_data['type'] == 'other':
                self.duration = self.workout_data['duration']
            else:
                self.sets = self.workout_data['sets']
                self.zippedSets = list(zip(self.workout_data['movements'],self.workout_data['sets']))
        else:
                self.zippedSets = list(zip(self.workout_data['movements'],self.workout_data['sets']))


    def __str__(self):
        return json.dumps(self.workout_data) ##could change this to the __dict__ maybe ?

#database thingssssss
#should allow for development using a dev database
if app.debug:
    DATABASE_URL = os.environ.get('DEV_DATABASE_URL')
    #database object instance 
    #db = Database(DATABASE_URL)
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

class ForgottenPassForm(FlaskForm):
    email = EmailField('Email: ',validators=[DataRequired()])
    submit = SubmitField("Submit")

class PasswordResetForm(FlaskForm):
    access_token = HiddenField("access_token")
    refresh_token = HiddenField("refresh_token")
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
        response = supabase.rpc("get_user_by_id_2",{"user_id":user_id}).execute()
        app.logger.info(f"USER LOADER SQL RESPONSE : {response}")

        user_data = response.data[0]

        if user_data:
            user_id = user_data['id']
            username = user_data['email']
            email = user_data['email']
            #the above used to be user_data.id and .email
        
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
            
            app.logger.info(f"USER INFO FOR LOGIN {sign_in.session}")
            if user_data:
                user_id = user_data.id
                username = user_data.email
                email = user_data.email
        
        # Create the User object
                current_user = User(user_id, username, email)
                flask_login.login_user(current_user)
                return redirect('/')
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


                                                                    #PROFILE

@app.route("/profile",methods=['GET','POST'])
@flask_login.login_required
def profile():
    current_user = flask_login.current_user  # Automatically set by Flask-Login
    #dashboard variable array ?
    dashboardInfo = {}
    lastmealObject = {}
    # Safely handle the user object
    if not current_user.is_authenticated:
        app.logger.info("User is not authenticated. Redirecting to login.")
        return redirect('/login')  # Redirect unauthenticated users
    
    #get the entries for this user 
    try:
        lastWokrout = supabase.rpc("get_workouts_by_user_2", {"p_user_id": current_user.id}).order("date", desc=True).limit(1).execute()
        app.logger.info(f"LAST WORKOUT:: {lastWokrout}")
        app.logger.info(f"LAST WORKOUT DATA:: {lastWokrout.data}")

        try:
            dashWorkout = Workout(lastWokrout.data[0])
            # app.logger.info(f"Last workout object = {dashWorkout}")
            dashboardInfo['workouts'] = [dashWorkout,]
        except Exception as e:
            app.logger.error(f"Last workout error = {e}")

        #last meal for dashboard
        lastMeal = supabase.table("macro_entry").select("*").eq("user_id", current_user.id).order("created", desc=True).limit(1).execute()
        app.logger.info(f"LAST MEAL:: {lastMeal.data}")
        try:
            lastmealObject['name'] = lastMeal.data[0]['entry_name']
            lastmealObject['data'] = lastMeal.data[0]['entry_data']
            #process the date for better formatting 
            lastmealObject['date'] = datetime.fromisoformat(lastMeal.data[0]['created'])
            # lastmealObject['date'] = lastMeal.data[0]['created']
            app.logger.info(f" SECOND MEAL OBJECT ::: {lastmealObject}")
            dashboardInfo['meals'] = [lastMeal.data,lastmealObject]
        except Exception as e:
            app.logger.error(f"Some went wrong adding meal to dashboard : {e}")

        #get last water response 
        waterObj = {}
        try:
            waterResponse = supabase.table("water").select("*").eq("user_id", current_user.id).order("created", desc=True).limit(1).execute()
            app.logger.info(f"LAST WATER INTAKE :: {waterResponse}")
            
            waterObj['amount'] = waterResponse.data[0]['entry_data']['amount'] 
            waterObj['date'] = datetime.fromisoformat(waterResponse.data[0]['entry_data']['date'])
            app.logger.info(f"WATER OBJECT TEST  :: {waterObj}")
            dashboardInfo['water'] = waterObj
        except Exception as e:
            app.logger.error(f" WATER RESPONSE ERROR :: {e}")

        #GET THE WORKOUT AND MEAL TOTALS 
        try:
            #might need the user id portion too
            response = supabase.table("user_activity_summary").select("*").eq("user_id",current_user.id).execute()
            app.logger.info(f"STATS RESPONSE == {response}")
            app.logger.info(f"STATS RESPONSE == {response.data}")
            dashboardInfo['stats'] = response.data
        except Exception as e:
            app.logger.error(f"Error when fetching stats {e}")

        app.logger.info(f" DASHBOARD :: {dashboardInfo}")

        workoutObjects = [] #can removw this now, BUT remove from template too

        return render_template("profile.html", user=current_user, workoutObjects = workoutObjects,dashboard = dashboardInfo)
    
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
        macroResponse = supabase.table("macro_entry").select("*").eq("user_id", current_user.id).order("created", desc=True).execute()
        macroEntries = macroResponse.data if macroResponse.data else []
        #format the created dates
        for entry in macroEntries:
            entry['created'] = format_date(entry['created'])
        return render_template("viewMeals.html",entries=macroEntries)
    except Exception as e:
        flash(e)
        return render_template("viewMeals.html")


@app.route("/view/workouts")
@flask_login.login_required
def viewWorkouts():

    try:
        workoutResponse = supabase.rpc("get_workouts_by_user_2", {"p_user_id": flask_login.current_user.id}).order("date", desc=True).execute()
        app.logger.info(f" WORKOUT RESPONSE :: {workoutResponse.data}")

        workoutObjects = []
        for w in workoutResponse.data:
            try:
                wobject = Workout(w)
                app.logger.info(f" WORKOUT OBJECT :: {wobject}")
                workoutObjects.append(wobject)
            except Exception as e:
                app.logger.info(f"Something wen wrong adding workouts {e}")
        # Render profile page for authenticated users
        return render_template("viewWorkouts.html", workoutObjects = workoutObjects)
    except Exception as e:
        flash(e)
        return redirect("/profile")




@app.route("/view/workout/<workout_id>",methods=['GET']) #workout id from supa is an int 
@flask_login.login_required
def viewWorkout(workout_id):
    #get the workout from supa
    try:
        response =  supabase.table("workout").select("*").eq('id',workout_id).maybe_single().execute()
        #check the user id too 
        if response:
            app.logger.info(f"Single workout response :: {response}")
            wjson = response.data['workout_json']
            wjson['id'] = response.data['id']
            app.logger.info(f" SINGLE OBJECT JSON = {wjson}")
        else:
            flash("No workout with that id exists")
            return render_template("viewWorkout.html")

        try:
            workoutObject = Workout(response.data)
            app.logger.info(f" SINGLE OBJECT = {workoutObject}")
            #flash(f"WORKOUT {workoutObject}")
            return render_template("viewWorkout.html",workout=workoutObject)
        
        except Exception as e:
            app.logger.info(f"Something wnet wronmg with single object {e}")
            flash(f"Something went wrong {e}")
            return render_template("viewWorkout.html")

        #show the page 
    except Exception as e:
        flash(f"Something went wrong {e}")
        return redirect("/profile")
    

@app.route("/waterEntry",methods=['GET','POST'])
@flask_login.login_required
def waterEntry():
    
    current_user = flask_login.current_user
    
    if request.method == 'POST':
        amount = request.form.get('amount')
        date = request.form.get('date')

        data = {
            "amount":amount,
            "date":date
        }

        waterObject = {
            'entry_data':data,
            "user_id": flask_login.current_user.id
        }
        app.logger.info(f"WATER INFO :: {data}")
        try:
            response = supabase.table("water").insert(waterObject).execute()
            app.logger.info(f"Water insert response = {response}")
            return redirect(url_for('waterEntry'))
        
        except Exception as e:
            flash(f"Something went wrong {e}")
            return redirect(url_for('waterEntry'))

    else:
        #get the water entries 
        waterEntries = []
        try:
            # response = supabase.table("water").select("*").eq("user_id", current_user.id).execute()
            response = supabase.table("water").select("*").eq("user_id", current_user.id).order("created", desc=True).execute()
            # app.logger.info(f"Water tracking select all == {response}")

            waterEntries = response.data if response.data else []

        except Exception as e :
            flash(f"Something went wrong {e}")
            return redirect(url_for('waterEntry'))

        return render_template("waterTracking.html",entries=waterEntries)

@app.route("/deleteWaterEntry/<entry_id>",methods=["GET"])
@flask_login.login_required
def deleteWaterEntry(entry_id):
    #GET ENTRY BY ID 
    #check the entry_id exists ?
    try:
        response = supabase.table("water").delete().eq("entry_id",entry_id).eq("user_id",flask_login.current_user.id).execute()
        app.logger.info(f"WATER DELETE RESPONSE {response}")
    except Exception as e:
        flash(f"Something went wrong {e}")
        return redirect(url_for('waterEntry'))
    
    return redirect(url_for('waterEntry'))

#delete workout 
@app.route("/deleteWorkoutEntry/<entry_id>",methods=["GET"])
@flask_login.login_required
def deleteWorkoutEntry(entry_id):
    #GET ENTRY BY ID 
    #check the entry_id exists ?
    try:
        response = supabase.table("workout").delete().eq("id",entry_id).eq("user_id",flask_login.current_user.id).execute()
        app.logger.info(f"WORKOUT DELETE RESPONSE {response}")
    except Exception as e:
        flash(f"Something went wrong {e}")
        return redirect(url_for('viewWorkouts'))
    
    return redirect(url_for('viewWorkouts'))


#delete meal entry 
@app.route("/deleteMealEntry/<entry_id>",methods=["GET"])
@flask_login.login_required
def deleteMealEntry(entry_id):
    #GET ENTRY BY ID 
    #check the entry_id exists ?
    try:
        response = supabase.table("macro_entry").delete().eq("entry_id",entry_id).eq("user_id",flask_login.current_user.id).execute()
        app.logger.info(f"MEAL DELETE RESPONSE {response}")
    except Exception as e:
        flash(f"Something went wrong {e}")
        return redirect(url_for('viewMeals'))
    
    return redirect(url_for('viewMeals'))



@app.route("/createMealEntry",methods=['GET','POST'])       #MEAL ENTRY 
@flask_login.login_required
def createMealEntry():

    if request.method == "POST":

        app.logger.info(f"REQUEST FORM DATA {request.form}")
        entryName =  clean(request.form.get('entryName'))
        #validate and ecape the name 

        macros = {
            "calories":0,
            "protein":0,
            "fats":0,
            "carbs":0,
            "fibre":0
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
            return redirect(url_for("createMealEntry"))

        return redirect(url_for("createMealEntry"))

    return render_template("createMealEntry.html")

@app.route("/add-workout",methods=['GET','POST'])
@flask_login.login_required
def addWorkout():

    if flask_login.current_user.is_authenticated: #probably dont need this 
        workoutObject = {}
        movementsObject = {}

        if request.method == 'POST':
            app.logger.info(f" WORKOUT ADD FORM == {request.form}")
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

            workoutObject['type'] = request.form.get("type")

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
            pastWorkouts = []
            try:
                lastWokrouts = supabase.rpc("get_workouts_by_user_2", {"p_user_id": flask_login.current_user.id}).order("date", desc=True).limit(7).execute()
                app.logger.info(f"LAST 7 WORKOUTS :: {lastWokrouts}")  

                #workoutObjects = []
                for w in lastWokrouts.data:
                    try:
                        wobject = Workout(w)
                        app.logger.info(f" WORKOUT OBJECT :: {wobject}")
                        pastWorkouts.append(wobject)
                    except Exception as e:
                        app.logger.info(f"Something wen wrong adding workouts {e}")
            except Exception as e:
                app.logger.info(f"SOMETHING WENT WRONG retreving WORKOUTs :: {e}")

            return render_template("addWorkout.html", pastWorkouts=pastWorkouts)

    # if request.method == 'GET':
    #     pastWorkouts = None
    #     try:
    #         lastWokrouts = supabase.rpc("get_workouts_by_user_2", {"p_user_id": flask_login.current_user.id}).order("date", desc=True).limit(7).execute()
    #         app.logger.info(f"LAST 7 WORKOUTS :: {lastWokrouts}")
    
    #         pastWorkouts = lastWokrouts
    #     except Exception as e:
    #         app.logger.info(f"SOMETHING WENT WRONG retreving WORKOUTs :: {e}")

    #     return render_template("addWorkout.html", pastWorkouts=pastWorkouts)

##alternate workout route 
@app.route("/add-workout-other",methods=['GET','POST'])
@flask_login.login_required
def addWorkoutOther():
    if flask_login.current_user.is_authenticated: #probably dont need this 
        workoutObject = {}
        #movementsObject = {}

        if request.method == 'POST':

            workoutObject['name'] = clean(request.form.get("workout-name"))
            workoutObject['date'] = request.form.get("date")
            workoutObject['duration'] = request.form.get("duration")
            workoutObject['calories-burned'] = request.form.get("cals-burned")
            workoutObject['distance'] = request.form.get("distance")
            workoutObject['type'] = request.form.get("type")

            app.logger.info(f"OTHER WORKOUT OBJECT = {workoutObject}")

            data = json.dumps(workoutObject)
            app.logger.info(f" WORKOUT :: {data}")

            supaData = {
                "workout_json":workoutObject,
                "user_id": flask_login.current_user.id
            }

            try:
                response = supabase.table("workout").insert(supaData).execute()
                app.logger.info(f"Workout added sucesfully :: ")
                return redirect(url_for('addWorkoutOther'))
            except Exception as e:
                app.logger.info(f"SOMETHING WENT WRONG ADDING WORKOUT :: {e}")

                flash(f"Something went wrong {e}")
                return redirect(url_for('addWorkoutOther'))

            return redirect("/add-workout-other")

    return render_template("otherWorkout.html")








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



@app.route("/profile/settings")
def profileSettings():
    return render_template("profileManagement.html")

@app.route("/forgottenPassword",methods=['GET','POST'])
def forgottenPassword():

    form = ForgottenPassForm()
    #check the token type ? 

    if request.method == "POST":
        email = request.form.get('email')
        try:
            response = supabase.auth.reset_password_for_email(email=email)
            flash("Recovery email sent")
            return redirect("/forgottenPassword")
        except Exception as e:
            flash(f"an error occurred. please try again {e}")
            return redirect("/forgottenPassword")
    else:
        return render_template("forgottenPassword.html",form=form)
    #redirect with flashed mesage saying email sent 



@app.route("/updatePassword", methods=['GET', 'POST'])      #FIX OR REMOVE THIS 
def updatePassword():

    token = request.args.get('access_token')
    token_type = request.args.get('type')
    refresh_token = request.args.get('refresh_token')
    app.logger.info(f"Access : {token}")
    app.logger.info(f"type: {token_type}")
    app.logger.info(f"Refresh: {refresh_token}")

    
    form = PasswordResetForm(access_token=token,refresh_token=refresh_token)

    if form.validate_on_submit():
        
        new_password = form.password.data
        access_token = form.access_token.data
        refresh_token = form.refresh_token.data
        app.logger.info(f"from form token :: {access_token}")

        try:

            response = supabase.auth.update_user({"password": new_password})
            #logout the user and have them relog in 
            flash("Password successfully updated.", "success")
            #log them out 
            return redirect("/login")

        except Exception as e:
            # Debugging: Log any errors
            app.logger.error(f"Error updating password: {e}")

            if "jwt expired" in str(e).lower():
                flash("The password reset link has expired. Please request a new one.", "danger")
            else:
                flash(f"An error occurred. Please try again. ERRO = {e}")

            return redirect("/forgottenPassword")

    return render_template("resetPassword.html", form=form)
    
@app.route("/welcome")
def welcome():
    return render_template("welcome.html")

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
    return redirect(url_for('welcome'))

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/about")
def about():
    return render_template("about.html")

#handle 404
@app.errorhandler(404)
def page_not_found(error):
    if app.debug:
        return error
    return render_template("404.html"),404

##handle all other errors
@app.errorhandler(Exception)
def handle_exception(error):
    return render_template("generic_error.html"),500

##for render to run 
if __name__ == "__main__":
    app.run()
    