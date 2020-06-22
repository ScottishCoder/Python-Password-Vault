from tkinter import *
from PIL import ImageTk, Image
from tkinter import ttk
import os
import random
import sqlite3
import pyAesCrypt
import string

# VauldDb class, contains CRUD methods
class Vaultdb():
	def __init__(self):
		# init conn to db
		self.conn = sqlite3.connect('passwordDB')
		# init the cursor to apply CRUD events
		self.cursor = self.conn.cursor()
		# create user table to differentiate between accounts
		self.cursor.execute('''CREATE TABLE IF NOT EXISTS user (user_id INTEGER PRIMARY KEY, username VARCHAR, password VARCHAR)''')
		self.conn.commit()
		# Create password table containing data of email used on vendor account plus their password
		self.cursor.execute('''CREATE TABLE IF NOT EXISTS password (password_id INTEGER PRIMARY KEY,email VARCHAR, vendor TEXT, password VARCHAR,password_user_id INTEGER,FOREIGN KEY(password_user_id) REFERENCES user(_id))''')
		self.conn.commit()



	# login method which checks username and password against user table in db
	def login(self,username,password):
		# login username
		self.username = username
		# login password
		self.password = password
		# Get user from DB
		self.cursor.execute('''SELECT user_id, username, password FROM user WHERE username=? AND password=?''',(self.username, self.password))
		self.conn.commit()
		# Fetch one record of such user
		success = self.cursor.fetchone()
		# if user does exist, run code within if
		if success:
			# debug print statement
			print('You Logged in')
			# creates global user id which can be used throughout app
			global loggedin_user_id
			# sets global user id and converts the int to a string, getting columm[0] user_id
			loggedin_user_id = str(success[0])
			# self.insertPassword('christroydeveloper@gmail.com', 'YouTube','Blapster887553')
			# self.select()
			return 0

		else:
			return 1
			# Wrong credentials provided
			print("Error. Either the account doesn't exist, or you have entered the wrong credentials")

	# Credential display method which simply grabs the user using global user id and displays logged in name
	def credentialDisplay(self,user_id):
		self.id = user_id
		self.cursor.execute('''SELECT username FROM user WHERE user_id = ?''',([self.id]))
		self.conn.commit()
		user = self.cursor.fetchone()
		return user

	# selects all passwords belonging to the logged in user
	def select(self):
		print(loggedin_user_id)
		rows = self.cursor.execute('''SELECT * FROM password WHERE password_user_id = ?''', [loggedin_user_id])
		self.conn.commit()

		return rows
				


	# Insert account method is used to add a new user to the DB
	def insertAccount(self, username, password):
		# verify check/validation
		self.username = username
		self.password = password
		self.cursor.execute('SELECT username, password FROM user WHERE username = ? AND password = ?', (self.username, self.password))
		self.conn.commit()
		result = self.cursor.fetchone()
		# if account exists, return message explaining problem
		if result:
			return 1
		else:
			# if account doesn't exist, add it to the DB
			self.cursor.execute('''INSERT INTO user (username, password) VALUES (?, ?)''',(self.username, self.password))
			self.conn.commit()


	# Insert Password method. This method inserts email, vendor and password belonging to the user
	def insertPassword(self, email, vendor, password):
		# verify check/validation to make sure no duplicates exist
		self.email = email
		self.vendor = vendor
		self.password = password
		self.cursor.execute('SELECT email, vendor, password FROM Password WHERE email = ? AND vendor = ? AND password = ? AND password_user_id = ?', (self.email, self.vendor, self.password, loggedin_user_id))
		self.conn.commit()
		result = self.cursor.fetchone()
		# if duplicate exists, explain problem to user
		if result:
			return 1
			print('We have a duplicate, and cannot add another')
		else:
			# no duplicate exists, so add the record to the db
			self.cursor.execute('''INSERT INTO password (password_user_id, email, vendor, password) VALUES (?, ?, ?, ?)''',(loggedin_user_id, self.email, self.vendor, self.password))
			self.conn.commit()
			

		
	# Delete method is used to remove unwanted records
	def delete(self, delete_id):
		# user provides ID index of record, which is used to target the tuple in the DB and delete it
		self.delete_id = delete_id
		self.cursor.execute('''DELETE FROM password WHERE password_id = ? AND password_user_id = ?''',(self.delete_id, loggedin_user_id))
		self.conn.commit()






# main class for application
class PythonVaultApp():
	# initilize the database and login window
	def __init__(self, vaultDB):
		self.db = vaultDB
		# IF THE PASSWORD DB IS ALREADY ENCRYPTED, DECRYPT IT
		if os.path.exists('passwordDB.aes'):
			self.decrypt()
			self.loginWindows()
		else:
			self.loginWindows()

	# Login windows method is used to display the login screen and retrieve input user data
	def loginWindows(self):
		# set db
		self.loginWindow = Tk()
		self.loginWindow.iconbitmap("icons/faviico.ico")
		# Program width at 1000 Pixels. Height at 500 Pixels
		self.loginWindow.geometry("1000x500")
		self.loginWindow.resizable(False, False)
		# Sets background colour of window to darkish blue
		
		self.loginWindow.title('TroySec Password Vault: Login')

		# background image login screen
		# # Label widget, sits inside our root window
		self.bg = Image.open('icons/appbg.jpg')
		self.bg = ImageTk.PhotoImage(self.bg)
		self.bgImage = Label(self.loginWindow, image=self.bg)
		self.bgImage.image=self.bg
		self.bgImage.place(x=-2, y=0)

		# # Label widget, sits inside our root window
		self.img = Image.open('icons/troyseclogo.png')
		self.img = ImageTk.PhotoImage(self.img)
		self.logo = Label(self.loginWindow, image=self.img, bg='#242e40')
		self.logo.image=self.img
		self.logo.place(x=375,y=8,width=250,height=200)

		self.loginWindow.configure(bg='#242e40')

		#username login and label
		self.usernameLabel = Label(self.loginWindow, text='Username:', bg='#242e40', fg='#a2a8ba')
		self.usernameLabel.place(x=347, y=185)
		# Entry , AKA input box. This input is for the username field
		self.usernameEntry = Entry(self.loginWindow)
		self.usernameEntry.place(x=350, y=210, width=300, height=40)

		#password login and label
		self.passwordLabel = Label(self.loginWindow, text='password:', bg='#242e40', fg='#a2a8ba')
		self.passwordLabel.place(x=347, y=255)
		# Entry , AKA input box. This input is for the password field
		self.passwordEntry = Entry(self.loginWindow)
		self.passwordEntry.place(x=350, y=280, width=300, height=40)

		# Login button. Contains Lambda function so that it only runs on call, multiple times if need be within mainloop
		self.loginButton = Button(self.loginWindow, text='Login', bg='#a2a8ba', fg='#242e40',command=lambda: self.loggedIn(self.usernameEntry.get(), self.passwordEntry.get()))
		self.loginButton.place(x=350, y=340, width=150, height=40)

		# Register button. Contains Lambda function so that it only runs on call, multiple times if need be within mainloop
		self.registerButton = Button(self.loginWindow, text='Register', bg='#a2a8ba', fg='#242e40', command=lambda: self.register(self.usernameEntry.get(), self.passwordEntry.get()))
		self.registerButton.place(x=501, y=340, width=150, height=40)


		# main loop of login window. Runs until X is used to close window, or until told using .destroy method
		self.loginWindow.mainloop()


	# register method is used to register new users on the program to the DB

	def register(self, username, password):
		# Call the databases insert account method. Pass in username and password

		self.result = self.db.insertAccount(username, password)
		print(self.result)
		# 1 means account already exists
		if self.result == 1:
			self.errorLabel = Label(self.loginWindow, text='An account with this Username and Password already exists',bg='#242e40', fg='#f24e4e')
			self.errorLabel.place(x=340, y=380)
		else:
			# If no duplicate exists, create the record by calling login method of database class
			self.db.login(username, password)
			# destroy the login window
			self.loginWindow.destroy()
			# open the main app window, passing in the database object so as to use the CRUD within the main screen
			self.app()

	def loggedIn(self, username, password):
		self.username = username
		self.password = password

		self.result = self.db.login(username, password)

		# 1 means account already exists
		if self.result == 1:
			self.errorLabel = Label(self.loginWindow, text='You have entered the wrong username and or password',bg='#242e40', fg='#f24e4e')
			self.errorLabel.place(x=340, y=380)
		else:
			# destroy the login window
			self.loginWindow.destroy()
			# open the main app window, passing in the database object so as to use the CRUD within the main screen
			self.app()



	# password generator is used to gen random passwords using a length provided by the user
	def passwordGenerator(self,userlen, customlen, var):
		self.userlen = userlen
		self.customlen = customlen
		self.var = var

		self.password = ''
		# List containing alphabet lowercase and uppercase, including nums 0-9 and special characters
		self.alphaPlus = ['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
		'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','0','1','2',
		'3','4','5','6','7','8','9','!','£','$','%','^','&','@','#','.',')','(','*','-','_','=','+','|']
		if self.userlen > 0:
			# run a loop using the provided length from the user
			for i in range(self.userlen):
				# pick a random char from the list, as long as its within the index range of 0-73
				self.picker = random.randint(0,73)
				# For every iteration, concatenate the indiviual char onto the password variable.
				self.password += self.alphaPlus[self.picker]
			# delete whatever is in the input box. This allows the generator to keep clearing it if they want to generate another.
			self.generatePasswordInsert.delete(0, END)
			# Input the randomly generated data into the input for the user to see and copy if need be.
			self.generatePasswordInsert.insert(0, self.password)
			self.var.set(0)
		elif int(self.customlen) > 0:

			# run a loop using the provided length from the user
			for i in range(int(self.customlen)):
				# pick a random char from the list, as long as its within the index range of 0-73
				self.picker = random.randint(0,73)
				# For every iteration, concatenate the indiviual char onto the password variable.
				self.password += self.alphaPlus[self.picker]
			# delete whatever is in the input box. This allows the generator to keep clearing it if they want to generate another.
			self.generatePasswordInsert.delete(0, END)
			# Input the randomly generated data into the input for the user to see and copy if need be.
			self.generatePasswordInsert.insert(0, self.password)
		else:
			print('Something weird happened')


	def addPassword(self,email,vendor,password, tree):
		self.email = email.replace(' ','')
		self.vendor = vendor.lower()
		self.password = password
		self.tree = tree
		self.errorLabel2 = Label(self.root, text='Please enter data into the corrosponding fields',bg='#242e40', fg='#f24e4e')
		self.errorLabel = Label(self.root, text='You have already stored this account and password.',bg='#242e40', fg='#f24e4e')
		self.successLabel = Label(self.root, text='Successfully added record into your vault database!',bg='#242e40', fg='#34c24a')
		
		if len(self.email) <= 5 or len(self.vendor) <= 5 or len(self.password) <= 5:

			self.successLabel.destroy()
			self.errorLabel.destroy()
			self.errorLabel2.place(x=127, y=327)

		else:
			result = self.db.insertPassword(self.email, self.vendor, self.password)
			if result == 1:				
				self.successLabel.destroy()
				self.errorLabel2.destroy()
				self.errorLabel.place(x=127, y=327)
			else:
				self.successLabel.place(x=127, y=327)
				tuples = self.db.select()

				for i in self.tree.get_children():
					self.tree.delete(i)

				self.bufferImg = []

	
				tuples = self.db.select()
				count = 0
				for userTuple in tuples:
					self.ico = Image.open('icons/lock.png')
					self.ico = ImageTk.PhotoImage(self.ico)
					self.bufferImg.append(self.ico)

					password_id = userTuple[0]
					email = userTuple[1]
					vendor = userTuple[2]
					password = userTuple[3]
					self.tree.insert('', 'end', image=self.bufferImg[count], value=(password_id, vendor, password, email))
					count += 1
		


	def deleteTuple(self, tuple_id, tree):
		self.tupleID = tuple_id
		self.tree = tree
		self.db.delete(self.tupleID)

		for i in self.tree.get_children():
			self.tree.delete(i)


		self.bufferImg = []
		tuples = self.db.select()
		count = 0
		
		for userTuple in tuples:
			self.ico = Image.open('icons/lock.png')
			self.ico = ImageTk.PhotoImage(self.ico)
			self.bufferImg.append(self.ico)

			password_id = userTuple[0]
			email = userTuple[1]
			vendor = userTuple[2]
			password = userTuple[3]
			self.tree.insert('', 'end', image=self.bufferImg[count], value=(password_id, vendor, password, email))
			count += 1


	def double_click_event(self, event):
		item = self.tree.selection()[0]
		recordID = self.tree.item(item).get('values')[0]
		self.deleteInsert.delete(0, END)
		self.deleteInsert.insert(0, str(recordID))

	# Main application
	def app(self):
		# call on credential display from the db object and pass in the global user id, acting as a session in a way.
		self.user = self.db.credentialDisplay(loggedin_user_id)
		# Our root window
		self.root = Tk()
		self.root.iconbitmap("icons/faviico.ico")
		self.root.geometry("1000x500")
		self.root.resizable(False, False)
		self.root.configure(bg='#242e40')
		self.root.title('TroySec Password Vault')

		# # Label widget, sits inside our root window
		self.img = Image.open('icons/padlock.png')
		self.img = ImageTk.PhotoImage(self.img)
		self.logo = Label(self.root, image=self.img)
		self.logo.image=self.img
		self.logo.place(x=330,y=8,width=32,height=32)
		self.logo.configure(bg='#242e40')


		# logo label for program
		self.logo = Label(self.root, text='TroySec Password Vault',bg='#242e40', fg='#a2a8ba')
		self.logo.config(font=("Arial", 22))
		self.logo.place(x=5,y=10)
		# Signed in label
		self.signedinLabel = Label(self.root, text='Logged in:',bg='#242e40', fg='#a2a8ba')
		self.signedinLabel.config(font=("Arial", 12))
		self.signedinLabel.place(x=400,y=10)
		#User signed in name label
		self.signedinName = Label(self.root, text=self.user,bg='#242e40', fg='#dbd116')
		self.signedinName.config(font=("Arial", 12))
		self.signedinName.place(x=480,y=10)

		#logout button
		self.logoutButton = Button(self.root, text='Encrypt & Logout', bg='#45c467',fg='#ffffff', activebackground="#fcba03", command=lambda: self.logout(self.root))
		self.logoutButton.place(x=870, y=10, width=120, height=30)
		# E-mail address label
		self.emailLabel = Label(self.root, text='E-mail', bg='#242e40', fg='#a2a8ba')
		self.emailLabel.config(font=("Arial", 12))
		self.emailLabel.place(x=5,y=99)
		# Email insert box
		self.emailEntry = Entry(self.root)
		self.emailEntry.place(x=8,y=125, width=400, height=40)

		# Vendor Label
		self.vendorLabel = Label(self.root, text='Vendor', bg='#242e40', fg='#a2a8ba')
		self.vendorLabel.config(font=("Arial", 12))
		self.vendorLabel.place(x=5,y=168)
		# Vendor insert box
		self.vendorEntry = Entry(self.root)
		self.vendorEntry.place(x=8,y=195, width=400, height=40)
		# Password Label
		self.passwordLabel = Label(self.root, text='Password', bg='#242e40',fg='#a2a8ba')
		self.passwordLabel.config(font=("Arial", 12))
		self.passwordLabel.place(x=5,y=238)
		# Password box
		self.passwordEntry = Entry(self.root)
		self.passwordEntry.place(x=8,y=265, width=400, height=40)
		#create a tkinter tree. Works better than Tkinter listbox as it allows image insertion
		self.tree = ttk.Treeview(column=('A','B','C','D'), selectmode='browse', height=7)
		# Button to init storage of user password assosiated with chosen vendor
		self.storeButton = Button(self.root, text='Store', bg='#a5aec7', activebackground="#fcba03", command=lambda: self.addPassword(self.emailEntry.get(), self.vendorEntry.get(), self.passwordEntry.get(), self.tree))
		self.storeButton.place(x=8, y=320, width=100, height=40)


		self.passwordGenLengthLabel = Label(self.root, text='Character length:', bg='#242e40', fg='#a5aec7')
		self.passwordGenLengthLabel.config(font=("Arial", 8))
		self.passwordGenLengthLabel.place(x=115,y=410)

		# radio buttons length gen password
		self.var = IntVar()
		self.radio1 = Radiobutton(self.root, text='8', variable=self.var, value=8, bg='#242e40', fg='#a5aec7')
		self.radio1.place(x=205,y=409)

		self.radio2 = Radiobutton(self.root, text='16', variable=self.var, value=16, bg='#242e40', fg='#a5aec7')
		self.radio2.place(x=240,y=409)

		self.radio3 = Radiobutton(self.root, text='32', variable=self.var, value=32, bg='#242e40', fg='#a5aec7')
		self.radio3.place(x=280,y=409)

		self.customGenLabel = Label(self.root, text='custom:', bg='#242e40', fg='#a5aec7')
		self.customGenLabel.place(x=320,y=409)

		self.customEntry = Entry(self.root)
		self.customEntry.place(x=370,y=412, width=50)



		# password gen label
		self.passwordGenLabel = Label(self.root, text='Generated Password:', bg='#242e40' , fg='#a5aec7')
		self.passwordGenLabel.config(font=("Arial", 8))
		self.passwordGenLabel.place(x=5,y=450)
		# Password gen insert box
		self.generatePasswordInsert = Entry(self.root)
		self.generatePasswordInsert.config(width=60)
		self.generatePasswordInsert.place(x=118, y=440, height=40)


		# generate button which inits the process in which a random pw is created for the user
		self.generateButton = Button(self.root, text='Generate', command=lambda: self.passwordGenerator(self.var.get(), self.customEntry.get(), self.var), bg='#a5aec7', activebackground="#fcba03")
		self.generateButton.place(x=490, y=440, width=100, height=40)

		# delete insert box
		self.deleteInsert = Entry(self.root)
		self.deleteInsert.config(width=10)
		self.deleteInsert.place(x=705, y=440, height=40)
		self.deleteInsert.config(fg= 'red')
		
		# Delete Button
		self.deleteButton = Button(self.root, text='Delete', bg='#f55b5b',fg='#ffffff', command=lambda: self.deleteTuple(self.deleteInsert.get(), self.tree))
		self.deleteButton.place(x=600, y=440, width=100, height=40)
		
		# sticky grid with north south east and west placement
		self.tree.grid(row=0, column=0, sticky='nsew')

		# Setup column heading
		self.tree.heading('#0', text='', anchor='center')
		self.tree.heading('A', text=' ID', anchor='center')
		self.tree.heading('B', text=' Vendor', anchor='center')
		self.tree.heading('C', text=' Password', anchor='center')
		self.tree.heading('D', text=' E-Mail', anchor='center')
		# #0, #01, #02 enotes the 0, 1st, 2nd columns
		self.tree.column('#0', anchor='center', width=25)
		self.tree.column('#1', anchor='center', width=30)
		self.tree.column('#2', anchor='center', width=80)
		self.tree.column('#3', anchor='center', width=80)
		self.tree.column('#4', anchor='center', width=150)
		self.tree.place(width=550, height=370, x=450, y=50)
		self.verscrlbar = ttk.Scrollbar(self.root,orient ="vertical",command = self.tree.yview)
		self.verscrlbar.pack(side ='right', fill ='x')

		
		for i in self.tree.get_children():
			self.tree.delete(i)

		self.bufferImg = []

	
		tuples = self.db.select()
		count = 0
		for userTuple in tuples:
			self.ico = Image.open('icons/lock.png')
			self.ico = ImageTk.PhotoImage(self.ico)
			self.bufferImg.append(self.ico)

			password_id = userTuple[0]
			email = userTuple[1]
			vendor = userTuple[2]
			password = userTuple[3]
			self.tree.insert('', 'end', image=self.bufferImg[count], value=(password_id, vendor, password, email))
			count += 1

		self.tree.bind("<Double-1>", self.double_click_event)
		# Call our loop, the main root (window) of the program
		self.root.mainloop()

		# Method which uses system random and strings libary to generate a random string key	
	def encryption_key_gen(self,size=16, chars=string.ascii_lowercase + string.ascii_uppercase + string.digits):
		# encryption/decryption buffer size - 64K
		bufferSize = 64 * 1024
		return ''.join(random.SystemRandom().choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(size))

	def encrypt(self):

		bufferSize = 64 * 1024
		key = self.encryption_key_gen()
		key_into_bytes = str.encode(key)
		hexed_key = key_into_bytes.hex()
		storeKey = open('encKey.bin', 'w')
		storeKey.write(hexed_key)
		storeKey.close()
		password = hexed_key
		# encrypt
		pyAesCrypt.encryptFile("passwordDB", "passwordDB.aes", password, bufferSize)
		os.remove('passwordDB')

	def decrypt(self):
		# # encryption/decryption buffer size - 64K
		bufferSize = 64 * 1024
		decodeKey = open('encKey.bin', 'rb')
		key_as_bytes = decodeKey.read()
		decode_tostring = key_as_bytes.decode()
		password = decode_tostring
		decodedKey = bytes.fromhex(decode_tostring).decode('utf-8')

		# decrypt
		pyAesCrypt.decryptFile("passwordDB.aes", "passwordDB", password, bufferSize)
		os.remove('passwordDB.aes')
		decodeKey.close()
		os.remove('encKey.bin')

	def logout(self, root):
		self.root = root
		self.root.destroy()
		self.db.conn.close()
		self.encrypt()


if __name__ == "__main__":
	print('This application requires the installation of an AES library for encryption purposes to secure your data')
	print('if you have it already, type (skip)')
	user = input('Will you allow the installation to proceed? y or n: ')
	if user == "y":
		os.system('pip install pyAesCrypt')
		database = Vaultdb()
		PythonVaultApp(database)
	elif user == 'skip':
		database = Vaultdb()
		PythonVaultApp(database)
	else:
		print('closing program. Without the AES library the data is not secured')
		exit()