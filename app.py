import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

#  PART OF DISTRIBUTION CODE!Configure application
app = Flask(__name__)

# PART OF DISTRIBUTION CODE! Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# PART OF DISTRIBUTION CODE! Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# PART OF DISTRIBUTION CODE! Custom filter
app.jinja_env.filters["usd"] = usd

#  PART OF DISTRIBUTION CODE!Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# PART OF DISTRIBUTION CODE! Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# PART OF DISTRIBUTION CODE! Make sure API key is set pk_d79f79be97ee48bc91d6ab0eec4e65e8
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user = session["user_id"]
    # Access data for user
    data = db.execute("SELECT symbol, shares FROM portfolio WHERE user_id = ?", user)
    current_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    # Define totals
    totalcash = current_cash
    totalprice = 0
    
    # Collect data for symbol, shares, total etc
    for item in data:
        symbol = item["symbol"]
        shares = float(item["shares"])
        quote = lookup(symbol)
        # add data
        item["name"] = str(quote["name"])
        item["price"] = float(quote["price"])
        item["total"] = item["price"] * shares
        totalprice += item["total"]
    balance = totalcash + totalprice
    return render_template("index.html", data=data, totalcash=totalcash, balance=balance)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        
        # Define variables
        user = session["user_id"]
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quote = lookup(symbol)
        
        # Check validity
        if not symbol:
            return apology("must provide symbol", 403)
        elif not quote:
            return apology("Invalid symbol", 400)
        elif not shares:
            return apology("must provide share amount", 403)
        elif not shares.isdigit():
            return apology("Invalid amount", 400)
        else:
            # Check for money
            purchase = lookup(symbol)["price"] * float(shares)
            current_cash = db.execute("SELECT cash FROM users WHERE id = ?", user)
            
            if not purchase <= current_cash[0]["cash"]:
                return apology("not enough cash", 403)
            else:
                # Record purchase in transactions:
                db.execute("INSERT INTO transactions (user_id, symbol, shares, time, type, price) VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'bought', ?)", 
                           user, symbol, shares, quote["price"])
                # Take money out
                rows = db.execute("SELECT cash FROM users WHERE id = ?", user)
                cash = rows[0]["cash"]
                db.execute("UPDATE users SET cash = ? WHERE id = ?", cash - purchase, user)
                # Update portfolio
                db.execute("INSERT INTO portfolio (user_id, symbol, shares) VALUES(?, ?, ?) ON CONFLICT(symbol) DO UPDATE SET shares = shares + ?", 
                           user, symbol, shares, shares)
                return redirect("/")
    else:
        # Buy share
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user = session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", user)
    
    return render_template("history.html", transactions=transactions)

#  PART OF DISTRIBUTION CODE!
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

# PART OF DISTRIBUTION CODE!
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        quote = lookup(symbol)
        if not symbol:
            return apology("must provide symbol", 400)
        elif not quote:
            return apology("invalid symbol", 400)
            
        return render_template("quoted.html", quote=quote)
        
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()
    # User reached route via POST
    if request.method == "POST":
        
        # Define inputs
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 400)
        
        # Ensure password is confirmed
        elif not confirmation:
            return apology("must confirm password", 400)
            
        # Ensure the two passwords match
        elif password != confirmation:
            return apology("password does not match", 400)
            
        # Check if username already exists    
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
        if len(rows) == 0:

            # Hash password
            hash = generate_password_hash(password)
        
            # Insert data
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
        
            return render_template("login.html")
        
        else:
            # If username taken
            return apology("username taken", 400)
    
    # User reached route via GET         
    else:
        return render_template("register.html")
        
        
@app.route("/change_pass", methods=["GET", "POST"])
@login_required
def change_pass():
    if request.method == "POST":
        # Define inputs
        user = session["user_id"]
        old = request.form.get("old")
        new = request.form.get("new")
        repeat = request.form.get("repeat")
        settings = db.execute("SELECT * FROM users WHERE id = ?", user)
        
        # Check validity
        if not old:
            return apology("must provide password", 403)
        elif not new:
            return apology("must provide password", 403)
        elif not repeat:
            return apology("must provide password", 403)
        elif new != repeat:
            return apology("password does not match", 403)
        elif not check_password_hash(settings[0]["hash"], request.form.get("old")):
            return apology("wrong password", 403)
        else:
            # Change password
            new_hash = generate_password_hash(new)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user)
            return redirect("/")
    else:
        return render_template("settings.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user = session["user_id"]
    wallet = db.execute("SELECT symbol, shares FROM portfolio WHERE user_id = ?", user)
    if request.method == "POST":
        
        # Define variables
        user = session["user_id"]
        symbol = request.form.get("symbol")
        shares = float(request.form.get("shares"))
        quote = lookup(symbol)
        sale = quote["price"] * shares
        wallet = db.execute("SELECT symbol, shares FROM portfolio WHERE user_id = ?", user)
        
        # Check validity
        if not symbol:
            return apology("must provide symbol", 403)
        elif not shares:
            return apology("must provide share amount", 403)
        elif not shares > 0:
            return apology("Invalid amount", 400)
        elif shares > wallet[0]["shares"]:
            return apology("not enough shares", 400)
        else:
            # Add money to user's balance
            rows = db.execute("SELECT cash FROM users WHERE id = ?", user)
            cash = rows[0]["cash"]
            db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + sale, user)
            # Take shares out of portfolio
            totshares = wallet[0]["shares"]
            db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?", totshares - shares, user, symbol)
            # Record transaction
            db.execute("INSERT INTO transactions (user_id, symbol, shares, time, type, price) VALUES (?, ?, ?, CURRENT_TIMESTAMP, 'sold', ?)", 
                       user, symbol, shares, quote["price"])
            return redirect("/")
    else:
        # Sell shares
        return render_template("sell.html", wallet=wallet)

# PART OF DISTRIBUTION CODE!
def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# PART OF DISTRIBUTION CODE! Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
