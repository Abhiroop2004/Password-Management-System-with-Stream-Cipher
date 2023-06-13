import os, datetime, pickle
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def keydev(p,salt): #hashes the master password
   kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=50000)
   key = kdf.derive(p)
   return key
   
def keycheck(key,salt,p): #checks the master password
   kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=salt,
      iterations=50000)
   try:
    if kdf.verify(p, key)==None:
          return True
   except:
      return False

def greet_user(): #quality of life addition, greeting the user
    current_time = datetime.datetime.now().time()
    hour = current_time.hour
    if 5 <= hour < 12:
        print("Good Morning!")
    elif 12 <= hour < 17:
        print("Good Afternoon!")
    elif 17 <= hour < 21:
        print("Good Evening!")
    else:
        print("Good Night!")
   
def strxor(a, b):  #str(key,value); xor two strings of different lengths, the Stream Cipher
    if len(a) > len(b):
       return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])

def searchfile(file,a): #searches for a password
   with open(file,'rb') as f:
      while True:
         try:
            r=pickle.load(f)
            if r[0].lower()==a.lower():
               return r[1]
         except EOFError:
            return None
            break

def changefile(file,a,k): #changes a password
   with open(file,'rb') as f:
      s=[]
      flag=0
      while True:
         try:
            s.append(pickle.load(f))
         except EOFError:
            break
      for l in s:
         if l[0].lower()==a.lower():
            flag=1
            new=input("Enter the new password:")
            l[1]=strxor(k,new)
            break
      if (flag==0):
         print("Sorry, application not found!\n")
   if flag==1:
      with open(file,'wb') as f:
         for l in s:
            pickle.dump(l,f)
      print("Password Changed Succesfully!\n")
      
def writefile(file,c): #creates and writes to the file for new user
   with open(file,'ab') as f:
      pickle.dump(c,f)

def main():
   print("------Welcome to Password Management System:------\n")
   greet_user()
   print()
   while(True):
      print(" 1: for new user")
      print(" 2: for existing user")
      print(" 3: to exit")
      print(" 4: for more info\n")
      c=int(input("Enter your Choice:"))

      if (c==1): #new user block
         name=input("Enter a username:")
         file=name+".dat"
         if os.path.exists(file): #checks if the username is available
            print("Sorry, This username already exists!") 
         else:
            p=bytes(input("Enter a master password for the document:"),'utf-8')
            salt=os.urandom(16)
            k=keydev(p,salt)
            content=[k,salt]
            writefile(file,content)
            print("Success! Continue as existing user to save passwords\n")

      elif (c==2): #existing user block
         name=input("Enter your username:")
         file=name+".dat"
         if os.path.exists(file): #checks if the username exists
            with open(file,'rb') as f:
                s=pickle.load(f)
            p=bytes(input("Enter your master password:"),'utf-8')
            if (keycheck(s[0],s[1],p)):
               print("\nEnter 1 to save a new password")
               print("Enter 2 to retrieve a saved password")
               print("Enter 3 to change a saved password\n")
               c=int(input("Enter choice:"))
               if c==1: #block to add a new password
                  m1=input("What is this password for? Enter the application name:")
                  m2=input("Enter the password:")
                  m2e=strxor(str(s[0]),m2)
                  m=[m1,m2e]
                  writefile(file,m)
                  print("Password Saved!\n")
               elif c==2: #block to retrieve a saved password
                  m1=input("Enter the application to retrieve the password of:")
                  m2e=searchfile(file,m1)
                  if (m2e != None):
                     p=strxor(str(s[0]),m2e)
                     print("The Required Password is:",p)
                  else:
                     print("Sorry, application not found!\n")
               elif c==3: #block to change a saved password
                  m1=input("Enter the application to change the password of:")
                  changefile(file,m1,str(s[0]))
               else:
                  print("Sorry, Wrong Choice!\n")
            else:
               print("Wrong Password!\n")
         else:
            print("Sorry wrong username!\n")

      elif (c==3): #exit block
         print("Thank you for choosing our Password Management System!")
         break

      elif (c==4): #info block
         print("\nINFO:")
         print("We have implemented strong security measures to protect your passwords.\nYour master password is securely hashed using the PBKDF2 algorithm and combined with a unique salt for added security.\nEach password you add is encrypted using a stream cipher, ensuring that your passwords are securely protected.\nThe hashed passwords and salts are stored in a binary format to enhance security.\nRemember to keep your master password strong and confidential, as it cannot be recovered or reset.")
         print("\nThank you for choosing our Password Management System!\n")

      else:
         print("Error, Wrong Choice!\n")
         continue

main()