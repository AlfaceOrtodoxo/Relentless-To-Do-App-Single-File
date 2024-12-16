from fastapi import FastAPI, Depends, HTTPException, Path
from pydantic import BaseModel, TypeAdapter
from sqlalchemy.orm import Session
from typing import List, Optional
from fastapi.security.oauth2 import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
import datetime
import flet as ft
import os
from sqlalchemy import Column, Integer, String, DateTime
from pydantic import BaseModel, ConfigDict, field_validator
from typing import Optional, List
from enum import Enum as PyEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from passlib.context import CryptContext
import jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer
from fastapi import Depends, HTTPException, status
from datetime import datetime, timedelta, date
from typing import Annotated
import requests

'''This is the Backend section written using FastAPI and SQLITE3.'''

#------------------------------------------------DATABASE----------------------------------------------

DATABASE_URL = "sqlite:///./to_do_app.db" # Nome do banco de dados

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

#----------------------------------------------DATABASE END--------------------------------------------
#----------------------------------------------MODELS--------------------------------------------------

class RecurrenceType(str, PyEnum):
    NONE = "none"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

# Base é uma classe da qual todos os modelos de banco de dados vão herdar.

class User(Base):                       # Classe User, representará a tabela de usuário
    __tablename__ = "users"             # Nome da tabela de banco de dados

    id = Column(Integer, primary_key=True, index=True)          # Coluna de ID único
    username = Column(String, unique=True, index=True)          # Nome de usuário
    password_hash = Column(String)                              # Hash de senha
    role = Column(String)                                       # Cargo
    

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key= True, index= True, autoincrement= True)      # Coluna de ID único
    title = Column(String(255), index= True)                                       # Título da tarefa
    description = Column(String, index= True)                                      # Descrição da tarefa
    status = Column(String(50), default="Pending")                                 # Status "pending" ou "completed"
    created_by = Column(String(255))                                               # Criador da tarefa
    assigned_to = Column(String(255))                                              # Responsável pela tarefa
    comments = Column(String, nullable= True)                                      # Comentários
    created_at = Column(DateTime, default= datetime.utcnow())             # Data de criação
    due_to = Column(DateTime)                                                      # Prazo
    recurrence_type = Column(String, default= "none")                              # "none", "daily", "weekly", "monthly" 
    recurrence_days = Column(String, nullable= True)                               # Dias da semana para tarefas semanais
    recurrence_end_date = Column(DateTime, nullable= True)                         # Término da recorrência                              

class TaskCreate(BaseModel):
    title: str
    description: str
    assigned_to: str
    comments: Optional[str] = None
    due_to: datetime
    recurrence_type: Optional[RecurrenceType] = RecurrenceType.NONE
    recurrence_days: Optional[List[str]] = None
    recurrence_end_date: Optional[datetime] = None

class TaskOut(BaseModel):
    id: int
    title: str
    description: str
    status: str
    created_by: str
    assigned_to: str
    comments: Optional[str] = None
    created_at: datetime
    due_to: datetime
    recurrence_type: RecurrenceType
    recurrence_days: Optional[List[str]] = None
    recurrence_end_date: Optional[datetime] = None

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        use_enum_values=True
    )

    @field_validator('recurrence_days', mode='before')
    def split_recurrence_days(cls, v):
        if v is None:
            return v
        if isinstance(v, str):
            return v.split(',')
        elif isinstance(v, list):
            return v
        else:
            raise ValueError("Invalid format for recurrence_days")

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    assigned_to: Optional[str] = None
    comments: Optional[str] = None
    due_to: Optional[datetime] = None
    status: Optional[str] = None
    recurrence_type: Optional[RecurrenceType] = None
    recurrence_days: Optional[List[str]] = None
    recurrence_end_date: Optional[datetime] = None

    model_config = ConfigDict(
        from_attributes=True,
        use_enum_values=True
    )

    @field_validator("recurrence_end_date", mode="before")
    def empty_string_to_none(cls, v):
        if v == "":
            return None
        return v

class Token(BaseModel):
    access_token: str
    token_type: str

#----------------------------------------------MODELS END----------------------------------------------
#----------------------------------------------AUTH UTILS----------------------------------------------

SECRET_KEY = "Relentless1!@#"

ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 30


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hashPassword(password: str) -> str:
    return pwd_context.hash(password)

def verifyPassword(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def createAccessToken(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "sub": data["sub"]})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def getCurrentUser(token: Annotated[str, Depends(oauth2_scheme)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        role = payload.get("role")
        if username is None:
            raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail = "Invalid Token.", headers = {"WWW-Authenticate": "Bearer"},)
        return username, role
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail = "Expired Token.", headers = {"WWW-Authenticate": "Bearer"},)

#----------------------------------------------AUTH UTILS END------------------------------------------





Base.metadata.create_all(bind=engine)

app = FastAPI()

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class UserLogin(BaseModel):
    username: str
    password: str

def getDb():
    db = SessionLocal()
    try:
        yield db

    finally:
        db.close()

def createRecurringTaskInstance(task, date):
    return TaskOut(
        id=task.id,
        title=task.title,
        description=task.description,
        status=task.status,
        created_by=task.created_by,
        assigned_to=task.assigned_to,
        comments=task.comments,
        created_at=datetime.now(),
        due_to=datetime.combine(date, task.due_to.time()),
        recurrence_type="none",
        recurrence_days=None,
        recurrence_end_date=None
    )

@app.get("/api/")
async def healthCheck():
    return "Ok, it's working. Please go to http://127.0.0.1:8000/docs to check and test the endpoints."

@app.post("/api/register")
async def registerUser(user: UserCreate, db: Session = Depends(getDb)):
    hashed_password = hashPassword(user.password)
    new_user = User(username = user.username, password_hash = hashed_password, role = user.role)
    db.add(new_user)
    db.commit()
    return {"msg": "User created successfully."}

@app.post("/api/login")
async def login(user_login: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(getDb)):
    
    print(user_login)
    # Procura o usuário no banco de dados:
    db_user = db.query(User).filter(User.username == user_login.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="User Not Found.")

    # Verifica a senha:
    if not verifyPassword(user_login.password, db_user.password_hash):
        raise HTTPException(status_code=400, detail= "Wrong Password.")
    
    # Cria o token JWT
    access_token = createAccessToken(data={"sub": db_user.username, "role": db_user.role})
    print(access_token)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/protected")
async def protectedRoute(current_user: str = Depends(getCurrentUser)):
    return {"message": f"Welcome, {current_user}!"}

@app.get("/api/users")
async def getEmployees(current_user: str = Depends(getCurrentUser), db: Session = Depends(getDb)):
    if not current_user:
        raise HTTPException(status_code=403, detail="Not Authorized.")
    
    if current_user[1] != "manager":
        raise HTTPException(status_code=403, detail="Management only.")
    
    employees = db.query(User).filter(User.role == "employee").all()

    if not employees:
        raise HTTPException(status_code=404, detail="No employees found.")
    
    usernames = [employee.username for employee in employees]

    return usernames

@app.delete("/api/delete")
async def deleteAccount(current_user: User = Depends(getCurrentUser), db: Session = Depends(getDb)):
    user = db.query(User).filter(User.username == current_user[0]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    
    db.delete(user)
    db.commit()
    return {"msg": "User account deleted successfully."}

@app.post("/api/tasks/", response_model= TaskOut)
def createTask(task: TaskCreate, db: Session = Depends(getDb), current_user: User = Depends(getCurrentUser)):
    if current_user[1] != "manager":
        raise HTTPException(status_code=403, detail="Not Authorized.")
    
    db_task = Task(
        title=task.title,
        description=task.description,
        created_by=current_user[0],
        assigned_to=task.assigned_to,
        comments=task.comments,
        due_to=task.due_to,
        recurrence_type=task.recurrence_type.value if task.recurrence_type else "none",
        recurrence_days=",".join(task.recurrence_days) if task.recurrence_days else None,
        recurrence_end_date=task.recurrence_end_date
    )
    
    db.add(db_task)
    db.commit()
    db.refresh(db_task)
    return db_task

@app.get("/api/tasks/", response_model=List[TaskOut])
def getTasks(status: Optional[str] = None, db: Session = Depends(getDb), current_user: User = Depends(getCurrentUser)):
    if not current_user or len(current_user) < 2:
        raise HTTPException(status_code=401, detail="Invalid user credentials.")

    username, role = current_user[0], current_user[1]

    if role == "employee":
        query = db.query(Task).filter(Task.assigned_to == username)
    elif role == "manager":
        query = db.query(Task).filter(Task.created_by == username)
    else:
        raise HTTPException(status_code=403, detail="Not authorized to view tasks.")

    if status and status.lower() != "all":
        query = query.filter(Task.status.ilike(status.lower()))

    tasks = query.all()

    # Lista para armazenar todas as tarefas, incluindo as recorrentes
    all_tasks = []

    today = datetime.today()

    for task in tasks:
        # Converter a tarefa original em modelo Pydantic
        task_pydantic = TaskOut.model_validate(task, from_attributes=True)
        all_tasks.append(task_pydantic)

        # Verificar se a tarefa é recorrente e gerar instâncias se necessário
        if task.recurrence_type != "none":
            if task.recurrence_type == "daily":
                if not task.recurrence_end_date or task.recurrence_end_date.date() >= today:
                    new_task = createRecurringTaskInstance(task, today)
                    all_tasks.append(new_task)
            elif task.recurrence_type == "weekly":
                if task.recurrence_days:
                    days = task.recurrence_days.split(",")
                    weekday = today.strftime('%a')
                    if weekday in days:
                        if not task.recurrence_end_date or task.recurrence_end_date.date() >= today:
                            new_task = createRecurringTaskInstance(task, today)
                            all_tasks.append(new_task)
            elif task.recurrence_type == "monthly":
                if task.due_to.day == today.day:
                    if not task.recurrence_end_date or task.recurrence_end_date.date() >= today:
                        new_task = createRecurringTaskInstance(task, today)
                        all_tasks.append(new_task)

    return all_tasks

@app.get("/api/tasks/{task_id}", response_model=TaskOut)
def getTask(task_id: int, db: Session = Depends(getDb), current_user: User = Depends(getCurrentUser)):
    username, role = current_user[0], current_user[1]

    # Buscar a tarefa pelo ID
    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Verificar autorização
    if role == "employee" and task.assigned_to != username:
        raise HTTPException(status_code=403, detail="Not authorized to view this task")
    elif role == "manager" and task.created_by != username:
        raise HTTPException(status_code=403, detail="Not authorized to view this task")

    # Converter a tarefa em modelo Pydantic
    task_pydantic = TaskOut.model_validate(task, from_attributes=True)

    return task_pydantic

@app.put("/api/tasks/{task_id}", response_model=TaskOut)
def updateTask(task_id: int, task_update: TaskUpdate, db: Session = Depends(getDb), current_user: User = Depends(getCurrentUser)):

    username, role = current_user[0], current_user[1]

    task = db.query(Task).filter(Task.id == task_id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    if role == "employee":
        if task.assigned_to != username:
            raise HTTPException(status_code=403, detail="You are not authorized to update this task.")
    elif role == "manager":
        if task.created_by != username and task.assigned_to != username:
            raise HTTPException(status_code=403, detail="You are not authorized to update this task.")
    else:
        raise HTTPException(status_code=403, detail="Not authorized to update tasks.")

    updated_fields = task_update.model_dump(exclude_unset=True)
    for field, value in updated_fields.items():
        setattr(task, field, value)

    if 'recurrence_type' in updated_fields and updated_fields['recurrence_type'] == 'none':
        task.recurrence_days = None
        task.recurrence_end_date = None

    try:
        db.commit()
        db.refresh(task)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while updating the task.")

    task_pydantic = TaskOut.model_validate(task, from_attributes=True)

    return task_pydantic

@app.delete("/api/tasks/{task_id}")
def deleteTask (task_id: int, db: Session = Depends(getDb), current_user: User = Depends(getCurrentUser)):
    
    username, role = current_user[0], current_user[1]
    
    task = db.query(Task).filter(Task.id == task_id).first()
    if task is None:
        raise HTTPException(status_code=404, detail= "Task Not Found")
    
    if role != "manager" and username != task.created_by:
        raise HTTPException(status_code=403, detail= "You are not authorized to delete this task.")

    db.delete(task)
    db.commit()
    return {"detail": "Task Deleted."}

#---------------------------------------------BACKEND END----------------------------------------

'''This is the frontend section written using Flet. '''

#----------------------------------------------AppColors--------------------------------------------------
class AppColors:
    button_icons_color = "#192a5a"
    button_bgcolor = "#ffffff"
    button_font_color = "#192a5a"
    button_color = "#192a5a"
    banner_text_color = "#192a5a"
    container_bgcolor = "#c9ccde"
    tasks_bgcolor = "#dbdde6"
    tasks_font_color = "#000000"
    hint_color = ft.colors.GREY_700
    error_message_color = ft.colors.RED
    field_bgcolor = "#353535"
    field_border_color = ft.colors.BLACK
    field_font_color = "#ffffff"
    page_bgcolor = "#c9ccde"
#----------------------------------------------AppColors End----------------------------------------------
#--------------------------------------------------Login--------------------------------------------------
class LoginPage:
    def __init__(self, page: ft.Page, on_login_success, on_register, back_register, logout):
        self.page = page
        self.token = None
        self.logout = logout
        self.page.fonts = {"RobotoSlab": "https://github.com/google/fonts/raw/main/apache/robotoslab/RobotoSlab%5Bwght%5D.ttf"}
        self.page.window.maximized = True
        self.on_login_success = on_login_success
        self.page.bgcolor = AppColors.page_bgcolor
        self.page.window.resizable = True
        self.page.window.always_on_top = False
        self.back_register = back_register
        self.on_register = on_register
        self.page.title = "Relentless To Do App"

        self.button_color = AppColors.button_color
        self.button_font_color = AppColors.button_font_color
        self.button_bgcolor = AppColors.button_bgcolor
        self.container_bgcolor = AppColors.container_bgcolor
        self.hint_color = AppColors.hint_color
        self.field_bgcolor = AppColors.field_bgcolor
        self.field_border_color = AppColors.field_border_color
        self.field_font_color = AppColors.field_font_color
        self.banner_text_color = AppColors.banner_text_color
        self.error_message_color = AppColors.error_message_color

        self.page.window.maximized = True

        self.login_title = ft.Text(
                value= "Login Page",
                font_family="RobotoSlab",
                color= self.banner_text_color,
                size= 40,
                weight= ft.FontWeight.W_700
            )

        self.failed_to_login = ft.Text(
                value="", 
                color= self.error_message_color,
                font_family="RobotoSlab",
                size=40,
                visible= True,
                text_align= ft.TextAlign.CENTER,
                style= ft.TextStyle.decoration_thickness
            )

        self.login_field = ft.TextField(
                hint_text="Username",
                hint_style=ft.TextStyle(color= self.hint_color),
                width= 400,
                bgcolor= self.field_bgcolor,
                border_color= self.field_border_color,
                color= self.field_font_color
            )
        
        self.password_field = ft.TextField(
                hint_text="Password",
                hint_style=ft.TextStyle(color= self.hint_color),
                width= 400,
                bgcolor= self.field_bgcolor,
                border_color= self.field_border_color,
                color= self.field_font_color,
                password= True
            )             

        self.login_button = ft.ElevatedButton(
                "SIGN IN", 
                icon= "login", 
                color= self.button_font_color,
                bgcolor= self.button_bgcolor,
                width= 130,
                on_click= self.onButtonClickLogin
            )
        
        self.register_button = ft.ElevatedButton(
                "SIGN UP", 
                icon= "arrow_forward_rounded", 
                color= self.button_font_color,
                bgcolor= self.button_bgcolor,
                width= 130,
                on_click= self.on_register
            )


    def loginPage(self):
        login = self.loginFields()
        self.page.add(login)
        self.page.update()
        return self.page

    def loginFields(self):
         return ft.Container(
            height= self.page.height,
            width= self.page.width,
            bgcolor= self.container_bgcolor,
            margin= 0,
            padding =200,
            alignment= ft.Alignment(0, -1),
            content= ft.Column(
                controls=[
                self.login_title,
                self.login_field,
                self.password_field,
                ft.Row(controls= [
                        self.login_button,
                        self.register_button,
                ],
                width= 400),
                self.failed_to_login], 
                spacing= 10
            )
        )
    
    def onButtonClickLogin(self, e=None):
        login_credentials = {
            "grant_type": "password",
            "username": self.login_field.value,
            "password": self.password_field.value,
            "scope": "",
            "client_id": "",
            "client_secret": ""
        }

        response = self.login(login_credentials)
        if response:
            print("Login successful:", response)
            self.on_login_success(response.get("access_token"))
        else:
            print("Login failed")        
    
    def login(self, params: dict):
        
        try:
            response = requests.post(
                url= "http://127.0.0.1:8000/api/login",
                data=params
            )
            
            if response.status_code == 200:
                self.token = response.json().get("access_token")
                print("Token received:", self.token)
                self.on_login_success(self.token)
                return response.json()
            else:
                error_message = f"Error {response.status_code}: {response.json().get('detail', 'Erro desconhecido')}"
                self.failed_to_login.value = error_message
                self.failed_to_login.visible = True
                self.page.update()
        except requests.RequestException as e:
            print("Error during login request: ", e)
            return None
#--------------------------------------------------Login End----------------------------------------------
#---------------------------------------------------Register----------------------------------------------
class RegisterPage:

    def __init__(self, page: ft.Page, on_register, back_register):
        self.page = page
        self.page.fonts = {"RobotoSlab": "https://github.com/google/fonts/raw/main/apache/robotoslab/RobotoSlab%5Bwght%5D.ttf"}
        self.page.window.maximized = True
        self.page.bgcolor = ft.colors.BLACK
        self.page.window.resizable = True
        self.page.window.always_on_top = False
        self.on_register = on_register
        self.back_register = back_register
        self.page.title = "Relentless To Do App"
        self.page.window.maximized = True
        self.page.update()


        self.button_color = AppColors.button_color
        self.button_font_color = AppColors.button_font_color
        self.button_bgcolor = AppColors.button_bgcolor
        self.container_bgcolor = AppColors.container_bgcolor
        self.hint_color = AppColors.hint_color
        self.field_bgcolor = AppColors.field_bgcolor
        self.field_border_color = AppColors.field_border_color
        self.field_font_color = AppColors.field_font_color
        self.banner_text_color = AppColors.banner_text_color
        self.error_message_color = AppColors.error_message_color

        self.register_title = ft.Text(
                value= "Register Page",
                font_family="RobotoSlab",
                color= self.banner_text_color,
                size= 40,
                weight= ft.FontWeight.W_700
            )

        self.failed_to_register = ft.Text(
                value="",
                font_family="RobotoSlab", 
                color= self.error_message_color,
                size=40,
                visible= False,
                text_align= ft.TextAlign.CENTER,
                style= ft.TextStyle.decoration_thickness
            )

        self.username_register = ft.TextField(
                hint_text="Choose your username",
                hint_style=ft.TextStyle(color= self.hint_color),
                bgcolor= self.field_bgcolor,
                border_color= self.field_border_color,
                color= ft.colors.BLACK,
                width= 400
            )
        
        self.password_register = ft.TextField(
                hint_text="Choose your password",
                hint_style=ft.TextStyle(color= self.hint_color),
                bgcolor= self.field_bgcolor,
                border_color= self.field_border_color,
                color=ft.colors.BLACK,
                password= True,
                width= 400
            )
        
        self.password_confirmation = ft.TextField(
                hint_text="Confirm your password",
                hint_style=ft.TextStyle(color= self.hint_color),
                bgcolor= self.field_bgcolor,
                border_color= self.field_border_color,
                color=ft.colors.BLACK,
                password= True,
                width= 400
            )
        
        self.role_choice = ft.Dropdown(
                value="Role",
                options= [ft.dropdown.Option("Employee", text_style= self.field_bgcolor), ft.dropdown.Option("Manager", text_style= self.field_bgcolor)],
                bgcolor= self.field_bgcolor,
                color= self.field_font_color,
                hint_text= "Role",
                hint_style=ft.TextStyle(color= self.hint_color),
                autofocus= True,
                border_color= self.field_border_color,
                alignment= ft.alignment.center_left,
                height= 40,
                width= 400,
                expand= True
            )
        
        self.register_button = ft.ElevatedButton(
                "SIGN UP", 
                icon= "arrow_outward_rounded", 
                color= self.button_font_color,
                bgcolor= self.button_bgcolor,
                on_click= self.onButtonClickRegister
            )
        
        self.back_button = ft.ElevatedButton(
                "BACK", 
                icon= "arrow_back_rounded", 
                color= self.button_font_color,
                bgcolor= self.button_bgcolor,
                on_click= self.onButtonClickBack
            )

        return None
    
    def registerPage(self):
        register = self.registerFields()
        return register
    
    def registerFields(self):
        
        return ft.Container(
            height= self.page.height,
            width= self.page.width,
            bgcolor= self.container_bgcolor,
            margin= 0,
            padding = 50,
            alignment= ft.Alignment(0,1),
            content= ft.Column(
                controls=[
                self.register_title,
                self.username_register,
                self.password_register,
                self.password_confirmation,
                self.role_choice,
                self.register_button,
                self.back_button,
                self.failed_to_register], 
                spacing= 10
            )
        )
    
    def onButtonClickBack(self, e=None):
        return self.back_register()

    def onButtonClickRegister(self, e=None):
        if not self.username_register.value:
            self.failed_to_register.value = "Username is required."
            self.failed_to_register.visible = True
            self.page.update()
            return
         
        if not self.password_register.value:
            self.failed_to_register.value = "Password is required."
            self.failed_to_register.visible = True
            self.page.update()
            return
    
        if not self.password_confirmation.value:
            self.failed_to_register.value = "Password confirmation is required."
            self.failed_to_register.visible = True
            self.page.update()
            return
    
        if not self.role_choice.value or self.role_choice.value == "Role":
            self.failed_to_register.value = "Role selection is required."
            self.failed_to_register.visible = True
            self.page.update()
            return
    
        register_credentials = {
            "username": self.username_register.value,
            "password": self.password_register.value,
            "role": self.role_choice.value.lower()  
        }

        response = self.register(register_credentials)
        if response:
            print("User registered successfully:", response)
        else:
            print("User register failed.")


    def register(self, params: dict):
        if self.password_register.value == self.password_confirmation.value:
                try:
                    response = requests.post(
                    url= "http://127.0.0.1:8000/api/register",
                    json=params
                    )
                    
                    if response.status_code == 200:
                        self.on_register()
                        return response.json()
                    else:
                        error_message = f"Error {response.status_code}: {response.json().get('detail', 'Erro desconhecido')}"
                        self.failed_to_register.value = error_message
                        self.failed_to_register.visible = True
                        self.page.update()
                except requests.RequestException as e:
                    print("Error during login request: ", e)
                    return None
        else:
            error_message = "The passwords don't match."
            self.failed_to_register.value = error_message
            self.failed_to_register.visible = True
            self.page.update()
#--------------------------------------------------Register End-------------------------------------------
#----------------------------------------------------Main Page--------------------------------------------
class MainPage:
    def __init__(self, page: ft.Page, token, add_task= None, edit_task= None, task_edited= None, task_added= None, back_add_task= None, logout=None):
        self.page = page
        self.token = token
        self.add_task = add_task
        self.logout = logout
        self.edit_task = edit_task
        self.task_edited = task_edited
        self.task_added = task_added
        self.back_add_task = back_add_task
        self.page.fonts = {"RobotoSlab": "https://github.com/google/fonts/raw/main/apache/robotoslab/RobotoSlab%5Bwght%5D.ttf"}
        self.page.window.maximized = True
        self.page.bgcolor = AppColors.page_bgcolor

        self.page.window.resizable = True
        self.page.window.always_on_top = False
        self.page.title = "Relentless To Do App"

        self.button_icons_color = AppColors.button_icons_color
        self.button_color = AppColors.button_color
        self.button_font_color = AppColors.button_font_color
        self.button_bgcolor = AppColors.button_bgcolor
        self.banner_text_color = AppColors.banner_text_color
        self.container_bgcolor = AppColors.container_bgcolor
        self.tasks_bgcolor = AppColors.tasks_bgcolor
        self.tasks_font_color = AppColors.tasks_font_color
        self.field_font_color = AppColors.field_font_color
        self.field_bgcolor = AppColors.field_bgcolor
        self.error_message_color = AppColors.error_message_color
        

        self.status_list = ["Pending", "Done", "All"]
        
        self.tabs = ft.Tabs(
                            selected_index=0,
                            tabs=[ft.Tab(text=status.upper()) for status in self.status_list],
                            on_change=self.onTabChange,
                            tab_alignment= ft.TabAlignment.CENTER,
                            width= self.page.width,
                            expand= True,
                            label_color= self.tasks_font_color,
                            overlay_color= self.field_bgcolor,
                            unselected_label_color= self.button_color,
                            indicator_color= self.container_bgcolor                            
                        )
        
        self.add_button = ft.ElevatedButton(
                            "ADD TASK",
                            icon="ADD", 
                            icon_color=self.button_icons_color,
                            color= self.button_font_color,
                            bgcolor= self.button_bgcolor,
                            on_click= self.add_task
                        )
        
        self.logout_button = ft.ElevatedButton(
                            "LOGOUT",
                            icon="logout_rounded", 
                            icon_color=self.button_icons_color,
                            color= self.button_font_color,
                            bgcolor= self.button_bgcolor,
                            on_click= self.logout
                        )
        
        self.head_text = ft.Text(
                            text_align= ft.TextAlign.CENTER,
                            font_family= "RobotoSlab", 
                            color= self.banner_text_color, 
                            size=40, 
                            value="Relentless To Do App - Welcome!",
                            weight= ft.FontWeight.W_700
                        )
        
        self.tasks_container = ft.Container(
                            height=self.page.height * 0.8,
                            width=self.page.width,
                            border_radius=0,
                            bgcolor= self.container_bgcolor,
                            margin=0,
                            alignment=ft.alignment.top_center,
                            content=ft.ListView(
                                controls=[],
                                spacing=10,
                                padding=10,
                                height= self.page.height * 0.7,
                            )
                        )

    def mainPage(self):
        head = self.headBanner()
        tabs = self.tabSelection()

        self.page.add(head, tabs, self.tasks_container)
        self.page.update()

        initial_status = self.status_list[self.tabs.selected_index]
        self.showTasks(initial_status)

    def getTasks(self, status=None):
        headers = {"Authorization": f"Bearer {self.token}"}

        params = {}

        if status and status != "All":
            params['status'] = status

        response = requests.get(url="http://127.0.0.1:8000/api/tasks/", headers=headers, params=params)
        try:
            if response.status_code == 200:
                return response.json()
            
            if response.status_code == 401:
                print(f'Your access token has expired. Please sign in again (Error: {response.status_code}, {response.text})')
                return []

            else:
                print(f"Unable to retrieve tasks. Error: {response.status_code}, {response.text}")
                return []
            
        except requests.RequestException as e:
            print(f'Failed request ({e})')
            return []

    def show_confirmation_dialog(self, task_id):
        confirmed = False

        def on_confirm(e):
            nonlocal confirmed
            confirmed = True
            self.page.dialog.open = False
            self.page.update()

            headers = {"Authorization": f"Bearer {self.token}"}
            response = requests.delete(
                url=f"http://127.0.0.1:8000/api/tasks/{task_id}",
                headers=headers
            )

            if response.status_code == 200:
                print(f"Task {task_id} deleted successfully.")
                self.getTasks()
            else:
                print(f"Failed to delete task {task_id}: {response.status_code} - {response.text}")


        def on_cancel(e):
            self.page.dialog.open = False
            self.page.update()

        dialog = ft.AlertDialog(
            modal=True,
            title=ft.Text("Confirm Deletion"),
            content=ft.Text("Are you sure you want to delete this task?"),
            actions=[
                ft.TextButton("Yes", on_click=on_confirm),
                ft.TextButton("No", on_click=on_cancel),
            ],
            actions_alignment=ft.MainAxisAlignment.END,
        )

        self.page.dialog = dialog
        dialog.open = True
        self.page.update()

    def headBanner(self):
        return ft.Container(
            height= self.page.height * 0.1,
            width= self.page.width,
            border_radius= 0,
            bgcolor= self.container_bgcolor,
            margin= 10,
            alignment= ft.alignment.center,
            content = ft.Row(
                            controls=[
                                        self.head_text,
                                        self.add_button,
                                        self.logout_button
                                    ],
                                vertical_alignment= ft.CrossAxisAlignment.CENTER,
                                alignment= ft.MainAxisAlignment.CENTER,
                                spacing= 30,
                                width= self.page.width
                                
                            )                                                          
                            )
    
    def onTabChange(self, e):
        selected_status = self.status_list[e.control.selected_index]
        self.showTasks(selected_status)
    
    def tabSelection(self):
        return ft.Container(
            height= self.page.height * 0.1,
            width= self.page.width,
            border_radius= 0,
            bgcolor= self.container_bgcolor,
            margin=0,
            alignment= ft.alignment.center,            


            content= self.tabs
        )

    def showTasks(self, status):
        tasks = self.getTasks(status)
        task_list_view = self.tasks_container.content
        task_list_view.controls.clear()

        for task in tasks:
            task_item = self.createTaskItem(task)
            task_list_view.controls.append(task_item)

        self.page.update()

    def deleteTask(self, task_id):

        confirm = self.show_confirmation_dialog(task_id)
        if not confirm:
            return

        headers = {"Authorization": f"Bearer {self.token}"}
        response = requests.delete(
            url=f"http://127.0.0.1:8000/api/tasks/{task_id}",
            headers=headers
        )

        if response.status_code == 200:
            print(f"Task {task_id} deleted successfully.")
            # Atualizar a lista de tarefas
            self.load_tasks()
        else:
            print(f"Failed to delete task {task_id}: {response.status_code} - {response.text}")

    def createTaskItem(self, task):
        def onEditTaskClick(e):
            self.edit_task(task["id"])

        edit_task_button = ft.FloatingActionButton(
            icon="edit",
            on_click=onEditTaskClick,
            bgcolor= self.banner_text_color
        )

        def onDeleteTaskClick(e):
            task_id = task.get("id")
            print(f"Deleting task with ID: {task_id}")
            if task_id is not None:
                self.deleteTask(task_id)
            else:
             print("Error: task_id is None")

        delete_task_button = ft.FloatingActionButton(
            icon="delete_rounded",
            on_click= onDeleteTaskClick,
            bgcolor= self.banner_text_color
        )

        task_item = ft.Container(
            padding=10,
            bgcolor=self.tasks_bgcolor,
            border_radius=5,
            margin=5,
            content=ft.Column(
                [
                    ft.Text(task["title"], color= self.tasks_font_color, size=20, weight= ft.FontWeight.W_600),
                    ft.Text(task["description"], color= self.tasks_font_color, size=16, weight= ft.FontWeight.W_600),
                    ft.Text(f"Status: {task['status']}", color= self.banner_text_color, size=14, weight= ft.FontWeight.W_600),
                    ft.Row([edit_task_button, delete_task_button]) 
                ]
            )
        )
        return task_item
#-------------------------------------------Main Page End-------------------------------------------------
#---------------------------------------------Add Task----------------------------------------------------
class AddTaskPage:
    def __init__(self, page: ft.Page, token, task_added, back_add_task):
        self.page = page
        self.token = token
        self.task_added = task_added
        self.back_add_task = back_add_task
        self.page.fonts = {"RobotoSlab": "https://github.com/google/fonts/raw/main/apache/robotoslab/RobotoSlab%5Bwght%5D.ttf"}
        self.page.window.maximized = True
        self.page.bgcolor = AppColors.page_bgcolor

        self.button_color = AppColors.button_color
        self.button_font_color = AppColors.button_font_color
        self.button_bgcolor = AppColors.button_bgcolor
        self.container_bgcolor = AppColors.container_bgcolor
        self.error_message_color = AppColors.error_message_color
        self.hint_color = AppColors.hint_color
        self.field_bgcolor = AppColors.field_bgcolor
        self.field_border_color = AppColors.field_border_color
        self.field_font_color = AppColors.field_font_color
        self.banner_text_color = AppColors.banner_text_color

        self.page.window.resizable = True
        self.page.window.always_on_top = True
        self.page.title = "Add Task"

        self.page_title = ft.Text(
            "Add Task",
            size= 40, 
            color= self.banner_text_color, 
            text_align= ft.TextAlign.CENTER, 
            font_family="RobotoSlab",
            weight= ft.FontWeight.W_700
        )

        self.create_task_button = ft.FloatingActionButton(
            icon="ADD",
            bgcolor= self.button_bgcolor,
            foreground_color= self.button_font_color,
            on_click=self.onButtonClickAddTask
        )

        self.back_button = ft.FloatingActionButton(
            icon= "arrow_back_rounded",
            bgcolor= self.button_bgcolor,
            foreground_color= self.button_font_color,
            on_click= self.onButtonClickBack
        )

        self.button_row = ft.Row(
            controls=[
                self.create_task_button,
                self.back_button
            ]
        )

        self.task_title_input = ft.TextField(
            hint_text="Task Title",
            hint_style=ft.TextStyle(color= self.hint_color),
            bgcolor= self.field_bgcolor,
            border_color= self.field_border_color,
            color= self.field_font_color,
            width=400
        )

        self.task_description_input = ft.TextField(
            hint_text="Task Description",
            hint_style=ft.TextStyle(color= self.hint_color),
            bgcolor= self.field_bgcolor,
            border_color= self.field_border_color,
            color= self.field_font_color,
            width=400,
            height=50
        )

        self.task_assigned_to_input = ft.Dropdown(
            value="Role",
            options=self.getEmployees(),
            bgcolor= self.field_bgcolor,
            color= self.field_font_color,
            hint_text="Assign task to:",
            hint_style=ft.TextStyle(color= self.hint_color),
            autofocus=False,
            border_color= self.field_border_color,
            alignment=ft.alignment.center_left,
            width=400,
            expand=False
        )

        self.task_comments_input = ft.TextField(
            hint_text="Comments",
            hint_style=ft.TextStyle(color= self.hint_color),
            bgcolor= self.field_bgcolor,
            border_color= self.field_border_color,
            color= self.field_font_color,
            width=400,
            height=50
        )

        self.task_due_to_input = ft.TextField(
            hint_text="Due Date",
            hint_style=ft.TextStyle(color= self.hint_color),
            bgcolor= self.field_bgcolor,
            border_color= self.field_border_color,
            color= self.field_font_color,
            width=400,
            read_only=1
        )

   
        self.calendar_button = ft.FloatingActionButton(
            'Pick Date',
            icon=ft.icons.CALENDAR_MONTH,
            bgcolor= self.button_bgcolor,
            foreground_color= self.button_font_color,
            on_click=self.openCustomDatePicker
        )

        self.failed_to_add_task = ft.Text(
                value="",
                font_family="RobotoSlab", 
                color= self.error_message_color,
                size=40,
                visible= False,
                text_align= ft.TextAlign.CENTER,
                style= ft.TextStyle.decoration_thickness,
                no_wrap= False
            )

        self.recurrence_type_input = ft.Dropdown(
            options=[
                    ft.dropdown.Option("none", "None"),
                    ft.dropdown.Option("daily", "Daily"),
                    ft.dropdown.Option("weekly", "Weekly"),
                    ft.dropdown.Option("monthly", "Monthly"),
                    ],
            hint_text="Recurrence Type",
            width=400,
            bgcolor= self.field_bgcolor,
            color= self.field_font_color,
            border_color= self.field_border_color,
            value="none",
            on_change=self.onRecurrenceTypeChange
        )

        self.weekday_checkboxes = [
            ft.Checkbox(label="Monday", value=False),
            ft.Checkbox(label="Tuesday", value=False),
            ft.Checkbox(label="Wednesday", value=False),
            ft.Checkbox(label="Thursday", value=False),
            ft.Checkbox(label="Friday", value=False),
            ft.Checkbox(label="Saturday", value=False),
            ft.Checkbox(label="Sunday", value=False),
        ]

        self.recurrence_days_container = ft.Column(

                controls=self.weekday_checkboxes,
                visible=False
            )

        self.recurrence_end_date_input = ft.TextField(

                hint_text="Recurrence End Date (YYYY-MM-DD)",
                visible=False,
                bgcolor= self.field_bgcolor,
                color= self.field_font_color,
            )

 
    def addTaskPage(self):
        task_fields = self.addTaskFields()
        self.page.add(task_fields)
        self.page.update()

    def onButtonClickBack(self, e=None):
        return self.back_add_task(self.token)

    def onRecurrenceTypeChange(self, e):
        if self.recurrence_type_input.value == "weekly":
            self.recurrence_days_container.visible = True
        else:
            self.recurrence_days_container.visible = False
        if self.recurrence_type_input.value != "none":
            self.recurrence_end_date_input.visible = True
        else:
            self.recurrence_end_date_input.visible = False
        self.page.update()

    def addTaskFields(self):
        return ft.Container(
            height=self.page.height,
            width=self.page.width,
            bgcolor= self.container_bgcolor,
            padding=50,
            alignment= ft.Alignment(1,0),
            content=ft.Column(
                controls=[
                    self.page_title,
                    self.task_title_input,
                    self.task_description_input,
                    self.task_assigned_to_input,
                    self.task_due_to_input,
                    self.calendar_button,
                    self.recurrence_type_input,
                    self.recurrence_days_container,
                    self.recurrence_end_date_input,     
                    self.button_row,
                    self.failed_to_add_task,

                ],
                alignment=ft.MainAxisAlignment.CENTER,
                wrap=False,
                scroll= True
            )

        )

    def openCustomDatePicker(self, e):

        day_options = [ft.dropdown.Option(str(i)) for i in range(1, 32)]
        month_options = [ft.dropdown.Option(str(i)) for i in range(1, 13)]
        current_year = datetime.now().year
        year_options = [ft.dropdown.Option(str(i)) for i in range(current_year, current_year + 5)]

        self.day_dropdown = ft.Dropdown(options=day_options, label="Day")
        self.month_dropdown = ft.Dropdown(options=month_options, label="Month")
        self.year_dropdown = ft.Dropdown(options=year_options, label="Year")

        ok_button = ft.ElevatedButton("OK", on_click=self.confirmDate)
        cancel_button = ft.ElevatedButton("Cancel", on_click=self.closeDialog)


        self.page.dialog = ft.AlertDialog(
            title=ft.Text("Select Due Date"),
            content=ft.Column(
                controls=[
                    self.month_dropdown,
                    self.day_dropdown,
                    self.year_dropdown,
                ],
                spacing=10,
                height= 200
            ),
            actions=[ok_button, cancel_button],
        )
        self.page.dialog.open = True
        self.page.update()

    def confirmDate(self, e):
        day = self.day_dropdown.value
        month = self.month_dropdown.value
        year = self.year_dropdown.value

        if day and month and year:
            try:
                
                selected_date = date(int(year), int(month), int(day))
                formatted_date = selected_date.strftime('%Y-%m-%d')

               
                self.task_due_to_input.value = formatted_date
                self.task_due_to_input.update()

                
                self.page.dialog.open = False
                self.page.update()
            except ValueError:
             
                self.page.dialog.content.controls.append(
                    ft.Text("Invalid date selected. Please try again.", color=ft.colors.RED)
                )
                self.page.dialog.update()
        else:
        
            self.page.dialog.content.controls.append(
                ft.Text("Please select day, month, and year.", color=ft.colors.RED)
            )
            self.page.dialog.update()
    
    def closeDialog(self, e):
        self.page.dialog.open = False
        self.page.update()

    def getEmployees(self):
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        response = requests.get(url="http://127.0.0.1:8000/api/users", headers=headers)
        employees = []
        if response.status_code == 200:
            employees_json = response.json()
            for employee in employees_json:
                employees.append(ft.dropdown.Option(employee, text_style=ft.colors.GREY_600))
        else:
            print(f"Failed to fetch employees: {response.status_code} - {response.text}")
        return employees

    def onButtonClickAddTask(self, e):

        try:
            parsed_due_date = datetime.strptime(self.task_due_to_input.value, '%Y-%m-%d')
            due_to_str = parsed_due_date.isoformat()
        except ValueError:
            self.failed_to_add_task.value = "Invalid due date format."
            self.failed_to_add_task.visible = True
            self.page.update()
            return
        
        recurrence_days = None

        if self.recurrence_type_input.value == "weekly":
            days_selected = []
            for checkbox in self.weekday_checkboxes:
                if checkbox.value:
                    days_selected.append(checkbox.label[:3])  # Usando abreviações, ex: 'Mon', 'Tue'
            recurrence_days = days_selected

            if not recurrence_days:
                self.failed_to_add_task.value = "Please select at least one day for weekly recurrence."
                self.failed_to_add_task.visible = True
                self.page.update()
                return

        # Verificar a data de término da recorrência se a recorrência não for 'none'
        recurrence_end_date = None
        if self.recurrence_type_input.value != "none":
            if not self.recurrence_end_date_input.value:
                self.failed_to_add_task.value = "Please enter a recurrence end date."
                self.failed_to_add_task.visible = True
                self.page.update()
                return
            try:
                recurrence_end_date = datetime.strptime(self.recurrence_end_date_input.value, '%Y-%m-%d')
            except ValueError:
                self.failed_to_add_task.value = "Invalid recurrence end date format."
                self.failed_to_add_task.visible = True
                self.page.update()
                return

        content = {
            "title": self.task_title_input.value,
            "description": self.task_description_input.value,
            "assigned_to": self.task_assigned_to_input.value,
            "comments": self.task_comments_input.value,
            "due_to": due_to_str,
            "recurrence_type": self.recurrence_type_input.value,
            "recurrence_days": recurrence_days,
            "recurrence_end_date": recurrence_end_date.isoformat() if recurrence_end_date else None
        }

        if not self.task_title_input.value:
            self.failed_to_add_task.value = "Task title required."
            self.failed_to_add_task.visible = True
            self.page.update()
            return
        
        if not self.task_description_input.value:
            self.failed_to_add_task.value = "Task description required."
            self.failed_to_add_task.visible = True
            self.page.update()
            return
        
        if not self.task_assigned_to_input.value:
            self.failed_to_add_task.value = "You must assign this task to someone."
            self.failed_to_add_task.visible = True
            self.page.update()
            return
        
        if not self.task_due_to_input.value:
            self.failed_to_add_task.value = "You must set a due date."
            self.failed_to_add_task.visible = True
            self.page.update()
            return
        
        
        
        response = self.addTask(content)
        if response:
            print('Task added successfully.')
        else:
            print('Failed to add task.')
        

    def addTask(self, params: dict):
        headers = {"Authorization": f"Bearer {self.token}"}

        try:
            response = requests.post(
                url= "http://127.0.0.1:8000/api/tasks/", 
                json=params,
                headers=headers
            )

            if response.status_code == 200:
                self.task_added(self.token)
                return response.json()
            else:
                error_message = f"Error {response.status_code}: {response.json().get('detail', 'Erro desconhecido')}"
                self.failed_to_add_task.value = error_message
                self.failed_to_add_task.visible = True
                print(error_message)
                self.page.update()
        except requests.RequestException as e:
                    print("Error during task adding request: ", e)
                    return None
#-------------------------------------------Add Task End--------------------------------------------------
#---------------------------------------------Edit Task---------------------------------------------------
class EditTaskPage:
    def __init__(self, page: ft.Page, token, task_id, edit_task, task_edited):
        self.page = page
        self.token = token
        self.task_id = task_id
        self.edit_task = edit_task
        self.task_edited = task_edited
        self.page.fonts = {"RobotoSlab": "https://github.com/google/fonts/raw/main/apache/robotoslab/RobotoSlab%5Bwght%5D.ttf"}
        self.page.window.maximized = True
        self.page.bgcolor = AppColors.page_bgcolor

        # Cores e estilos
        self.button_color = AppColors.button_color
        self.button_font_color = AppColors.button_font_color
        self.button_bgcolor = AppColors.button_bgcolor        
        self.container_bgcolor = AppColors.container_bgcolor
        self.error_message_color = AppColors.error_message_color
        self.hint_color = AppColors.hint_color
        self.field_bgcolor = AppColors.field_bgcolor
        self.field_border_color = AppColors.field_border_color
        self.field_font_color = AppColors.field_font_color
        self.banner_text_color = AppColors.banner_text_color

        self.page.window.resizable = True
        self.page.window.always_on_top = True
        self.page.title = "Edit Task"

        # Componentes de Interface
        self.page_title = ft.Text(
            "Edit Task",
            size=40, 
            color=self.banner_text_color, 
            text_align=ft.TextAlign.CENTER, 
            font_family="RobotoSlab",
            weight=ft.FontWeight.W_700
        )
        
        self.task_title_input = ft.TextField(
            hint_text="Task Title",
            hint_style=ft.TextStyle(color=self.hint_color),
            bgcolor=self.field_bgcolor,
            border_color=self.field_border_color,
            color=self.field_font_color,
            width=400
        )

        self.task_description_input = ft.TextField(
            hint_text="Task Description",
            hint_style=ft.TextStyle(color=self.hint_color),
            bgcolor=self.field_bgcolor,
            border_color=self.field_border_color,
            color=self.field_font_color,
            width=400,
            height=50
        )

        self.task_assigned_to_input = ft.Dropdown(
            options=self.getEmployees(),
            bgcolor=self.field_bgcolor,
            color=self.field_font_color,
            hint_text="Assign To",
            hint_style=ft.TextStyle(color=self.field_font_color),
            border_color=self.field_border_color,
            width=400
        )

        self.task_comments_input = ft.TextField(
            hint_text="Comments",
            hint_style=ft.TextStyle(color=self.hint_color),
            bgcolor=self.field_bgcolor,
            border_color=self.field_border_color,
            color=self.field_font_color,
            width=400,
            height=50
        )

        self.task_due_to_input = ft.TextField(
            hint_text="Due Date (YYYY-MM-DD)",
            hint_style=ft.TextStyle(color=self.hint_color),
            bgcolor=self.field_bgcolor,
            border_color=self.field_border_color,
            color=self.field_font_color,
            width=400,
            read_only=True
        )

        self.calendar_button = ft.FloatingActionButton(
            'Pick Date',
            icon=ft.icons.CALENDAR_MONTH,
            bgcolor=self.button_bgcolor,
            foreground_color=self.button_font_color,
            on_click=self.openCustomDatePicker,
        )

        self.task_status_input = ft.Dropdown(
            options=[
                ft.dropdown.Option("Pending"),
                ft.dropdown.Option("Done")
            ],
            bgcolor=self.field_bgcolor,
            color=self.field_font_color,
            hint_text="Status",
            hint_style=ft.TextStyle(color=self.hint_color),
            border_color=self.field_border_color,
            width=400
        )

        self.save_button = ft.FloatingActionButton(
            "Save",
            icon=ft.icons.SAVE,
            bgcolor=self.button_bgcolor,
            foreground_color=self.button_font_color,
            on_click=self.onSaveButtonClick
        )

        self.cancel_button = ft.FloatingActionButton(
            "Cancel",
            icon=ft.icons.CANCEL,
            bgcolor=self.button_bgcolor,
            foreground_color=self.button_font_color,
            on_click=self.onCancelButtonClick
        )

        self.failed_to_edit_task = ft.Text(
            value="",
            color=self.error_message_color,
            visible=False,
            text_align=ft.TextAlign.CENTER,
            font_family="RobotoSlab",
            size=20
        )

        self.recurrence_type_input = ft.Dropdown(
            options=[
                ft.dropdown.Option("none", "None"),
                ft.dropdown.Option("daily", "Daily"),
                ft.dropdown.Option("weekly", "Weekly"),
                ft.dropdown.Option("monthly", "Monthly"),
            ],
            hint_text="Recurrence Type",
            width=400,
            value="none",
            bgcolor=self.field_bgcolor,
            color=self.field_font_color,
            border_color=self.field_border_color,
            on_change=self.onRecurrenceTypeChange
        )

        self.weekday_checkboxes = [
            ft.Checkbox(label="Monday", value=False),
            ft.Checkbox(label="Tuesday", value=False),
            ft.Checkbox(label="Wednesday", value=False),
            ft.Checkbox(label="Thursday", value=False),
            ft.Checkbox(label="Friday", value=False),
            ft.Checkbox(label="Saturday", value=False),
            ft.Checkbox(label="Sunday", value=False),
        ]

        self.recurrence_days_container = ft.Column(
            controls=self.weekday_checkboxes,
            visible=False
        )

        self.recurrence_end_date_input = ft.TextField(
            hint_text="Recurrence End Date (YYYY-MM-DD)",
            hint_style=ft.TextStyle(color=self.hint_color),
            visible=False,
            bgcolor=self.field_bgcolor,
            color=self.field_font_color,
            width=400
        )

    def editTaskPage(self):
        self.loadTaskData()
        task_fields = self.editTaskFields()
        self.page.add(task_fields)
        self.page.update()

    def editTaskFields(self):
        return ft.Container(
            height=self.page.height,
            width=self.page.width,
            bgcolor=self.container_bgcolor,
            padding=50,
            alignment=ft.Alignment(1, 0),
            content=ft.Column(
                controls=[
                    self.page_title,
                    self.task_title_input,
                    self.task_description_input,
                    self.task_assigned_to_input,
                    self.task_status_input,
                    self.task_due_to_input,
                    self.recurrence_type_input,
                    self.recurrence_days_container,
                    self.recurrence_end_date_input,
                    self.calendar_button,
                    self.task_comments_input,
                    ft.Row(
                        controls=[self.save_button, self.cancel_button],
                        alignment=ft.MainAxisAlignment.START
                    ),
                    self.failed_to_edit_task
                ],
                alignment=ft.MainAxisAlignment.START,
                scroll=True
            )
        )
    
    def onRecurrenceTypeChange(self, e):
        if self.recurrence_type_input.value == "weekly":
            self.recurrence_days_container.visible = True
        else:
            self.recurrence_days_container.visible = False

        if self.recurrence_type_input.value != "none":
            self.recurrence_end_date_input.visible = True
        else:
            self.recurrence_end_date_input.visible = False
            self.recurrence_end_date_input.value = ""
        self.page.update()

    def loadTaskData(self):
        headers = {"Authorization": f"Bearer {self.token}"}

        response = requests.get(
            url=f"http://127.0.0.1:8000/api/tasks/{self.task_id}",
            headers=headers
        )
        if response.status_code == 200:
            task = response.json()
            print("Dados da Tarefa:", task)  # Para debugging

            # Preencher os campos de entrada
            self.task_title_input.value = task.get("title", "")
            self.task_description_input.value = task.get("description", "")
            self.task_assigned_to_input.value = task.get("assigned_to", "")
            self.task_comments_input.value = task.get("comments", "")
            self.task_due_to_input.value = task["due_to"][:10] if task.get("due_to") else ""
            self.task_status_input.value = task.get("status", "")
            self.recurrence_type_input.value = task.get("recurrence_type", "none")

            # Handle recurrence_days
            recurrence_days = task.get("recurrence_days", [])
            if isinstance(recurrence_days, str):
                recurrence_days = [day.strip() for day in recurrence_days.split(",")]
            print("Recurrence Days (processed):", recurrence_days)

            # Atualizar os checkboxes dos dias da semana
            if recurrence_days:
                for checkbox in self.weekday_checkboxes:
                    # Usa apenas as três primeiras letras para correspondência
                    checkbox.value = checkbox.label[:3] in recurrence_days
            else:
                # Se não houver dias de recorrência, desmarcar todos os checkboxes
                for checkbox in self.weekday_checkboxes:
                    checkbox.value = False

            # Handle recurrence_end_date
            recurrence_end_date = task.get("recurrence_end_date")
            print("Recurrence End Date (raw):", recurrence_end_date)
            if recurrence_end_date:
                # Verifica se a data está no formato esperado antes de fatiar
                if isinstance(recurrence_end_date, str) and len(recurrence_end_date) >= 10:
                    self.recurrence_end_date_input.value = recurrence_end_date[:10]
                else:
                    self.recurrence_end_date_input.value = ""
            else:
                self.recurrence_end_date_input.value = ""

            # Definir a visibilidade do campo de data de término de recorrência
            if self.recurrence_type_input.value in ["daily", "weekly", "monthly"]:
                self.recurrence_end_date_input.visible = True
            else:
                self.recurrence_end_date_input.visible = False
                self.recurrence_end_date_input.value = ""

            self.page.update()
        else:
            self.failed_to_edit_task.value = f"Failed to load task: {response.status_code} - {response.text}"
            self.failed_to_edit_task.visible = True
            self.page.update()

    def onSaveButtonClick(self, e):
        # Input validation
        if not self.task_title_input.value:
            self.failed_to_edit_task.value = "Task title is required."
            self.failed_to_edit_task.visible = True
            self.page.update()
            return

        if not self.task_description_input.value:
            self.failed_to_edit_task.value = "Task description is required."
            self.failed_to_edit_task.visible = True
            self.page.update()
            return

        if not self.task_assigned_to_input.value:
            self.failed_to_edit_task.value = "You must assign this task to someone."
            self.failed_to_edit_task.visible = True
            self.page.update()
            return

        if not self.task_due_to_input.value:
            self.failed_to_edit_task.value = "You must set a due date."
            self.failed_to_edit_task.visible = True
            self.page.update()
            return

        # Parse and validate the due date
        try:
            parsed_due_date = datetime.strptime(self.task_due_to_input.value, '%Y-%m-%d')
            due_to_str = parsed_due_date.isoformat()
        except ValueError:
            self.failed_to_edit_task.value = "Invalid due date format."
            self.failed_to_edit_task.visible = True
            self.page.update()
            return
        
        recurrence_days = None

        if self.recurrence_type_input.value == "weekly":
            days_selected = []
            for checkbox in self.weekday_checkboxes:
                if checkbox.value:
                    days_selected.append(checkbox.label[:3])  # Usando abreviações, ex: 'Mon', 'Tue'
            recurrence_days = days_selected

            if not recurrence_days:
                self.failed_to_edit_task.value = "Please select at least one day for weekly recurrence."
                self.failed_to_edit_task.visible = True
                self.page.update()
                return

        # Verificar a data de término da recorrência se a recorrência não for 'none'
        recurrence_end_date = None
        recurrence_end_date_str = None
        if self.recurrence_type_input.value != "none":
            if not self.recurrence_end_date_input.value:
                self.failed_to_edit_task.value = "Please enter a recurrence end date."
                self.failed_to_edit_task.visible = True
                self.page.update()
                return
            try:
                recurrence_end_date = datetime.strptime(self.recurrence_end_date_input.value, '%Y-%m-%d')
                recurrence_end_date_str = recurrence_end_date.isoformat()
            except ValueError:
                self.failed_to_edit_task.value = "Invalid recurrence end date format."
                self.failed_to_edit_task.visible = True
                self.page.update()
                return

        updated_data = {
            "title": self.task_title_input.value,
            "description": self.task_description_input.value,
            "assigned_to": self.task_assigned_to_input.value,
            "comments": self.task_comments_input.value,
            "due_to": due_to_str,
            "status": self.task_status_input.value.title(),
            "recurrence_type": self.recurrence_type_input.value,
            "recurrence_days": recurrence_days,
            "recurrence_end_date": recurrence_end_date_str if recurrence_end_date else None
        }

        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        response = requests.put(
            url=f"http://127.0.0.1:8000/api/tasks/{self.task_id}",
            json=updated_data,
            headers=headers
        )

        if response.status_code == 200:
            # Success
            self.task_edited(self.token)  # Navigate back or refresh the main page
        else:
            # Handle errors
            self.failed_to_edit_task.value = f"Failed to edit task: {response.status_code} - {response.text}"
            self.failed_to_edit_task.visible = True
            self.page.update()

    def onCancelButtonClick(self, e):
        self.task_edited(self.token)

    def openCustomDatePicker(self, e):
        day_options = [ft.dropdown.Option(str(i)) for i in range(1, 32)]
        month_options = [ft.dropdown.Option(str(i)) for i in range(1, 13)]
        current_year = datetime.now().year
        year_options = [ft.dropdown.Option(str(i)) for i in range(current_year, current_year + 5)]

        self.day_dropdown = ft.Dropdown(options=day_options, label="Day")
        self.month_dropdown = ft.Dropdown(options=month_options, label="Month")
        self.year_dropdown = ft.Dropdown(options=year_options, label="Year")

        ok_button = ft.ElevatedButton("OK", on_click=self.confirmDate)
        cancel_button = ft.ElevatedButton("Cancel", on_click=self.closeDialog)

        self.page.dialog = ft.AlertDialog(
            title=ft.Text("Select Due Date"),
            content=ft.Column(
                controls=[
                    self.month_dropdown,
                    self.day_dropdown,
                    self.year_dropdown,
                ],
                spacing=10,
                height=200
            ),
            actions=[ok_button, cancel_button],
        )
        self.page.dialog.open = True
        self.page.update()
    
    def confirmDate(self, e):
        day = self.day_dropdown.value
        month = self.month_dropdown.value
        year = self.year_dropdown.value

        if day and month and year:
            try:
                selected_date = date(int(year), int(month), int(day))
                formatted_date = selected_date.strftime('%Y-%m-%d')

                self.task_due_to_input.value = formatted_date
                self.task_due_to_input.update()

                self.page.dialog.open = False
                self.page.update()
            except ValueError:
                # Remover mensagens de erro anteriores para evitar duplicação
                self.page.dialog.content.controls = [
                    self.month_dropdown,
                    self.day_dropdown,
                    self.year_dropdown,
                    ft.Text("Invalid date selected. Please try again.", color=ft.colors.RED)
                ]
                self.page.dialog.update()
        else:
            # Remover mensagens de erro anteriores para evitar duplicação
            self.page.dialog.content.controls = [
                self.month_dropdown,
                self.day_dropdown,
                self.year_dropdown,
                ft.Text("Please select day, month, and year.", color=ft.colors.RED)
            ]
            self.page.dialog.update()
    
    def closeDialog(self, e):
        self.page.dialog.open = False
        self.page.update()

    def getEmployees(self):
        headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}
        response = requests.get(url="http://127.0.0.1:8000/api/users", headers=headers)
        employees = []
        if response.status_code == 200:
            employees_json = response.json()
            for employee in employees_json:
                employees.append(ft.dropdown.Option(employee, text_style=ft.TextStyle(color= self.field_font_color)))
        else:
            print(f"Failed to fetch employees: {response.status_code} - {response.text}")
        return employees
#-------------------------------------------Edit Task End-------------------------------------------------
#----------------------------------------Relentless To Do App---------------------------------------------

class RelentlessToDoApp:
    def __init__(self, page: ft.Page):
        self.page = page
        self.page.title = "Relentless To Do App"
        self.page.window.maximized = True
        self.page.update()
        self.showLoginPage()
    
    def onLoginSuccess(self, token):
        self.showMainPage(token)

    def showLoginPage(self, e=None):
        self.page.clean()
        self.login_page = LoginPage(self.page, on_login_success=self.showMainPage, on_register=self.showRegisterPage, back_register= self.showLoginPage, logout= None)
        self.login_page.loginPage()

    def showRegisterPage(self, e=None):
        self.page.controls.clear()
        self.register_page = RegisterPage(self.page, on_register=self.showLoginPage, back_register= self.showLoginPage).registerPage()
        self.page.add(self.register_page)
        self.page.update()

    def showMainPage(self, token):
        self.token = token
        self.page.clean()
        main_page = MainPage(self.page, token, add_task=self.showAddTaskPage, edit_task= self.showEditTaskPage, task_added=self.showMainPage, logout=self.showLoginPage)
        main_page.mainPage()

    def showAddTaskPage(self, e=None):
       self.page.clean()
       add_task_page = AddTaskPage(self.page, token=self.token, task_added=self.showMainPage, back_add_task=self.showMainPage)
       add_task_page.addTaskPage()

    def showEditTaskPage(self, task_id):
        self.page.clean()
        edit_task_page = EditTaskPage(self.page, token=self.token, task_id=task_id, edit_task=None, task_edited=self.showMainPage)
        edit_task_page.editTaskPage()


def run_flet_app(page: ft.Page):
    RelentlessToDoApp(page)

if __name__ == "__main__":  
    ft.app(target=RelentlessToDoApp)



