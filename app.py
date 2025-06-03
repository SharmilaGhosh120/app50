# -*- coding: utf-8 -*-
import os
import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
import requests
import logging
import time
import uuid
import re
import csv
import io
import bcrypt
from dotenv import load_dotenv

# Check if reportlab is available
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import Table, TableStyle, SimpleDocTemplate, Paragraph
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# Load environment variables (fallback to relative path for Streamlit Cloud)
load_dotenv()
DB_PATH = os.getenv('DB_PATH', 'kyra.db')

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Rate Limiting Configuration
CALLS = 10
PERIOD = 60

# Authentication Functions
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_user(email, password):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT password_hash, name, role FROM users WHERE email = ?', (email,))
        result = c.fetchone()
        conn.close()
        if not result:
            return None, "Email not found."
        stored_hash = result[0].encode()
        if bcrypt.checkpw(password.encode(), stored_hash):
            return {"name": result[1], "role": result[2]}, None
        return None, "Incorrect password."
    except sqlite3.Error as e:
        logger.error(f"Database error in verify_user: {str(e)}")
        return None, "Database error. Please try again."

def reset_user_password(email, new_password):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        password_hash = hash_password(new_password)
        c.execute('UPDATE users SET password_hash = ? WHERE email = ?', (password_hash, email))
        if c.rowcount == 0:
            conn.close()
            return False, "User not found."
        conn.commit()
        conn.close()
        return True, "Password reset successfully."
    except sqlite3.Error as e:
        logger.error(f"Database error in reset_user_password: {str(e)}")
        return False, "Database error. Please try again."

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(pattern, email) is not None

# Database Utility Functions
def get_project_for_student(email, conn):
    cursor = conn.cursor()
    cursor.execute("SELECT project_title FROM student_project_map spm JOIN projects p ON spm.project_id = p.project_id WHERE spm.student_id = ?", (email,))
    result = cursor.fetchone()
    return result[0] if result else "No Project Assigned"

def get_unique_students(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT email, name FROM users WHERE role = 'student'")
    return cursor.fetchall()

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT,
                role TEXT,
                password_hash TEXT
            )
        ''')

        c.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in c.fetchall()]
        if 'password_hash' not in columns:
            c.execute('ALTER TABLE users ADD COLUMN password_hash TEXT')

        c.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                project_id TEXT PRIMARY KEY,
                email TEXT,
                project_title TEXT,
                timestamp TEXT,
                FOREIGN KEY (email) REFERENCES users(email)
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS queries (
                query_id TEXT PRIMARY KEY,
                email TEXT,
                name TEXT,
                project_title TEXT,
                question TEXT,
                response TEXT,
                timestamp TEXT,
                feedback_rating INTEGER,
                FOREIGN KEY (email) REFERENCES users(email)
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS student_project_map (
                student_id TEXT,
                project_id TEXT,
                timestamp TEXT,
                PRIMARY KEY (student_id, project_id),
                FOREIGN KEY (student_id) REFERENCES users(email),
                FOREIGN KEY (project_id) REFERENCES projects(project_id)
            )
        ''')

        default_admin = ('admin@college.edu', 'Jane Admin', 'admin', hash_password('default123'))
        c.execute('INSERT OR IGNORE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)', default_admin)
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {str(e)}")
        st.error("Failed to initialize database. Please contact support.")

def save_user(email, name, password=None, role="student"):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        password_hash = hash_password(password) if password else None
        if password:
            c.execute('INSERT OR REPLACE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                     (email, name, role, password_hash))
        else:
            c.execute('UPDATE users SET name = ?, role = ? WHERE email = ?',
                     (name, role, email))
        conn.commit()
        conn.close()
        return True, "User saved successfully."
    except sqlite3.Error as e:
        logger.error(f"Database error in save_user: {str(e)}")
        return False, "Database error. Please try again."

def save_query(email, name, question, response, conn):
    try:
        query_id = str(uuid.uuid4())
        project_title = get_project_for_student(email, conn)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM queries WHERE email = ? AND question = ? AND timestamp = ?', (email, question, timestamp))
        if not cursor.fetchone():
            cursor.execute('INSERT INTO queries (query_id, email, name, project_title, question, response, timestamp, feedback_rating) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                          (query_id, email, name, project_title, question, response, timestamp, None))
            conn.commit()
    except sqlite3.Error as e:
        logger.error(f"Database error in save_query: {str(e)}")
        st.error("Failed to save query. Please try again.")

def save_project(email, project_title):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        project_id = str(uuid.uuid4())
        c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                 (project_id, email, project_title, timestamp))
        c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                 (email, project_id, timestamp))
        conn.commit()
        conn.close()
        return True, "Project saved successfully."
    except sqlite3.Error as e:
        logger.error(f"Database error in save_project: {str(e)}")
        return False, "Database error. Please try again."

def get_user_projects(email):
    try:
        conn = sqlite3.connect(DB_PATH)
        user_projects = pd.read_sql_query("SELECT project_title, timestamp FROM projects WHERE email = ? ORDER BY timestamp DESC",
                                        conn, params=(email,))
        conn.close()
        return user_projects
    except sqlite3.Error as e:
        logger.error(f"Database error in get_user_projects: {str(e)}")
        return pd.DataFrame()

def delete_user(email):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('DELETE FROM users WHERE email = ?', (email,))
        if c.rowcount == 0:
            conn.close()
            return False, "User not found."
        conn.commit()
        conn.close()
        return True, "User deleted successfully."
    except sqlite3.Error as e:
        logger.error(f"Database error in delete_user: {str(e)}")
        return False, "Database error. Please try again."

def export_query_logs_to_csv(student_email=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        query = "SELECT email, name, project_title, question, response, timestamp, feedback_rating FROM queries"
        if student_email:
            query += " WHERE email = ?"
            query_logs = pd.read_sql_query(query, conn, params=(student_email,))
        else:
            query_logs = pd.read_sql_query(query, conn)
        conn.close()
        if not query_logs.empty:
            csv_data = query_logs.to_csv(index=False).encode('utf-8')
            return csv_data, "Query logs exported successfully!"
        return None, "No query logs available."
    except sqlite3.Error as e:
        logger.error(f"Database error in export_query_logs_to_csv: {str(e)}")
        return None, "Database error while fetching query logs."

def export_query_logs_to_pdf(student_email=None):
    if not REPORTLAB_AVAILABLE:
        return None, "PDF export is unavailable."
    try:
        conn = sqlite3.connect(DB_PATH)
        query = "SELECT email, name, project_title, question, response, timestamp, feedback_rating FROM queries"
        if student_email:
            query += " WHERE email = ?"
            query_logs = pd.read_sql_query(query, conn, params=(student_email,))
        else:
            query_logs = pd.read_sql_query(query, conn)
        conn.close()

        if query_logs.empty:
            logger.warning("No query logs found for PDF export.")
            return None, "No query logs available."

        # Prepare data for the table
        data = [["Email", "Name", "Project Title", "Question", "Response", "Timestamp", "Feedback Rating"]]
        for _, row in query_logs.iterrows():
            rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
            data.append([
                row['email'],
                row['name'],
                row['project_title'],
                row['question'],
                row['response'],
                row['timestamp'],
                rating
            ])

        # Create PDF in memory
        buffer = io.BytesIO()
        try:
            doc = SimpleDocTemplate(buffer, pagesize=letter)
            style = getSampleStyleSheet()
            elements = []
            elements.append(Paragraph("Query Logs Report", style['Title']))

            col_widths = [80, 80, 80, 100, 120, 80, 60]
            table = Table(data, colWidths=col_widths, repeatRows=1)
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
            ]))
            elements.append(table)
            doc.build(elements)
            pdf_data = buffer.getvalue()
            buffer.close()
            return pdf_data, "Query logs exported successfully!"
        except Exception as e:
            logger.error(f"Error generating PDF with reportlab: {str(e)}")
            buffer.close()
            return None, "Failed to generate PDF. Please try again."
    except sqlite3.Error as e:
        logger.error(f"Database error in export_query_logs_to_pdf: {str(e)}")
        return None, "Database error while fetching query logs."

def bulk_register_users(csv_file):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        reader = csv.DictReader(io.StringIO(csv_file.read().decode('utf-8')))
        required_columns = ['email', 'name', 'role']
        if not all(col in reader.fieldnames for col in required_columns):
            return False, "CSV must contain 'email', 'name', and 'role' columns."
        for row in reader:
            email = row['email'].strip()
            name = row['name'].strip()
            role = row['role'].strip()
            if not email or not name or not role:
                return False, f"Missing data in row: {email}"
            if not is_valid_email(email):
                return False, f"Invalid email format: {email}"
            if role not in ['student', 'admin']:
                return False, f"Invalid role for {email}: {role}"
            password = 'default123'
            password_hash = hash_password(password)
            c.execute('INSERT OR IGNORE INTO users (email, name, role, password_hash) VALUES (?, ?, ?, ?)',
                     (email, name, role, password_hash))
        conn.commit()
        conn.close()
        return True, "Users registered successfully!"
    except Exception as e:
        logger.error(f"Error processing CSV: {str(e)}")
        return False, f"Error processing CSV: {str(e)}"

# Streamlit page configuration
st.set_page_config(
    page_title="Ask Ky’ra",
    page_icon=":robot_face:",
    layout="centered"
)

# Custom CSS for styling
st.markdown(
    """
    <style>
    .main {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        font-family: 'Roboto', sans-serif;
    }
    .stTextInput > div > input {
        border: 1px solid #ccc;
        border-radius: 5px;
        font-family: 'Roboto', sans-serif;
    }
    .stTextArea > div > textarea {
        border: 1px solid #ccc;
        border-radius: 5px;
        font-family: 'Roboto', sans-serif;
    }
    .submit-button {
        display: flex;
        justify-content: center;
    }
    .submit-button .stButton > button {
        background-color: #4fb8ac;
        color: white;
        font-size: 18px;
        padding: 10px 20px;
        border-radius: 8px;
        width: 200px;
        font-family: 'Roboto', sans-serif;
    }
    .history-entry {
        padding: 15px;
        border: 1px solid #e0e0e0;
        border-radius: 12px;
        background-color: white;
        margin-bottom: 10px;
        box-shadow: 1px 1px 3px #ccc;
        font-family: 'Roboto', sans-serif;
        word-wrap: break-word;
        overflow-wrap: break-word;
        max-width: 100%;
    }
    .chat-container {
        max-height: 400px;
        overflow-y: auto;
        padding: 10px;
        border: 1px solid #e0e0e0;
        border-radius: 12px;
        background-color: #f9f9f9;
    }
    .chat-footer {
        text-align: center;
        font-family: 'Roboto', sans-serif;
        color: #4fb8ac;
        margin-top: 20px;
    }
    .avatar {
        display: inline-block;
        width: 30px;
        height: 30px;
        border-radius: 50%;
        background-color: #4fb8ac;
        color: white;
        text-align: center;
        line-height: 30px;
        font-family: 'Roboto', sans-serif;
        margin-right: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Initialize database
init_db()

# Display logo and subtitle
with st.container():
    logo_url = "https://raw.githubusercontent.com/SharmilaGhosh120/app16/main/WhatsApp%20Image%202025-05-20%20at%2015.17.59.jpeg"
    try:
        response = requests.head(logo_url, timeout=5)
        if response.status_code == 200:
            st.image(logo_url, width=100, caption="Ky’ra Logo")
            st.markdown("<h3 style='text-align: center; font-family: \"Roboto\", sans-serif;'>Ky’ra – Your Personalized AI Assistant</h3>", unsafe_allow_html=True)
        else:
            logger.warning("Unable to load Ky’ra logo. URL inaccessible.")
            st.warning("Unable to load Ky’ra logo.")
    except Exception as e:
        logger.warning(f"Failed to load logo: {str(e)}")
        st.warning("Unable to load Ky’ra logo.")
st.markdown("---", unsafe_allow_html=True)

# Initialize session state
if "email" not in st.session_state:
    st.session_state.email = ""
if "name" not in st.session_state:
    st.session_state.name = ""
if "role" not in st.session_state:
    st.session_state.role = ""
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
if "page" not in st.session_state:
    st.session_state.page = 1
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False

# Logout Functionality
if st.session_state.authenticated:
    if st.button("Logout"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.success("You have been logged out successfully!")
        st.rerun()
st.markdown("---", unsafe_allow_html=True)

# Login interface
if not st.session_state.authenticated:
    st.subheader("Login to Ask Ky’ra")
    email_input = st.text_input("Email", placeholder="admin@college.edu")
    password_input = st.text_input("Password", type="password", placeholder="Enter your password")
    if st.button("Login"):
        if email_input and password_input:
            user_info, error = verify_user(email_input, password_input)
            if user_info:
                st.session_state.authenticated = True
                st.session_state.email = email_input
                st.session_state.name = user_info["name"]
                st.session_state.role = user_info["role"]
                st.success(f"Login successful! Welcome, {user_info['name']}!")
                st.rerun()
            else:
                st.error(error)
        else:
            st.error("Please enter both email and password.")
else:
    # User Details Section
    st.subheader("Your Details")
    email_input = st.text_input("Email", value=st.session_state.email, placeholder="student123@college.edu", disabled=True)
    name_input = st.text_input("Your Name", value=st.session_state.name, placeholder="Enter your name")
    password_input = st.text_input("New Password (optional)", type="password", placeholder="Set or update password")
    if st.button("Update Details"):
        if name_input:
            success, message = save_user(st.session_state.email, name_input, password_input, st.session_state.role)
            if success:
                st.session_state.name = name_input
                st.success(message)
            else:
                st.error(message)
        else:
            st.error("Please enter your name.")
    st.markdown("---", unsafe_allow_html=True)

    # Admin-specific features
    if st.session_state.role == "admin":
        st.subheader("Manage Users")
        new_email = st.text_input("New User Email", placeholder="newstudent@college.edu")
        new_name = st.text_input("New User Name", placeholder="Enter new user name")
        new_role = st.selectbox("Role", ["student", "admin"])
        new_password = st.text_input("New User Password", type="password", placeholder="Set password")
        if st.button("Register User"):
            if not new_email or not new_name or not new_password:
                st.error("Please fill in all fields for the new user.")
            elif not is_valid_email(new_email):
                st.error("Please enter a valid email address.")
            else:
                success, message = save_user(new_email, new_name, new_password, new_role)
                if success:
                    st.success(f"{message} User: {new_name} ({new_email})")
                else:
                    st.error(message)
        st.markdown("---", unsafe_allow_html=True)

        st.subheader("Reset User Password")
        conn = sqlite3.connect(DB_PATH)
        users = get_unique_students(conn)
        conn.close()
        if users:
            reset_email = st.selectbox("Select User to Reset Password", [email for email, _ in users],
                                      format_func=lambda x: f"{x} ({[name for email, name in users if email == x][0]})")
            reset_password = st.text_input("New Password", type="password", placeholder="Enter new password")
            if st.button("Reset Password"):
                if not reset_password:
                    st.error("Please provide a new password.")
                elif not is_valid_email(reset_email):
                    st.error("Invalid email address.")
                else:
                    if st.checkbox("Confirm password reset"):
                        success, message = reset_user_password(reset_email, reset_password)
                        if success:
                            st.success(f"{message} for {reset_email}")
                        else:
                            st.error(message)
                    else:
                        st.warning("Please confirm the password reset.")
        else:
            st.info("No students available.")
        st.markdown("---", unsafe_allow_html=True)

        st.subheader("Delete User")
        conn = sqlite3.connect(DB_PATH)
        users = get_unique_students(conn)
        conn.close()
        if users:
            delete_email = st.selectbox("Select User to Delete", [email for email, _ in users],
                                       format_func=lambda x: f"{x} ({[name for email, name in users if email == x][0]})")
            if st.button("Delete User"):
                if st.checkbox("Confirm user deletion"):
                    success, message = delete_user(delete_email)
                    if success:
                        st.success(message)
                    else:
                        st.error(message)
                else:
                    st.warning("Please confirm the user deletion.")
        else:
            st.info("No students available to delete.")
        st.markdown("---", unsafe_allow_html=True)

        st.subheader("Bulk Register Users")
        uploaded_user_file = st.file_uploader("Upload a CSV file (email,name,role)", type=["csv"])
        if uploaded_user_file is not None:
            success, message = bulk_register_users(uploaded_user_file)
            if success:
                st.success(message)
            else:
                st.error(message)
        st.markdown("---", unsafe_allow_html=True)

    # Format timestamp
    def format_timestamp(timestamp_str):
        try:
            dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            return dt.strftime("%B %d, %Y %I:%M %p")
        except ValueError:
            return timestamp_str

    # Admin Dashboard
    def show_admin_dashboard(name):
        st.markdown(f"<h1 style='text-align: center; color: #4fb8ac; font-family: \"Roboto\", sans-serif;'>🎓 Welcome College Admin, {name}!</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; font-family: \"Roboto\", sans-serif;'>Manage student mappings, projects, and reports with Ky’ra.</p>", unsafe_allow_html=True)

        # Display Statistics
        try:
            conn = sqlite3.connect(DB_PATH)
            total_users = pd.read_sql_query("SELECT COUNT(*) AS count FROM users WHERE role = 'student'", conn)['count'][0]
            total_projects = pd.read_sql_query("SELECT COUNT(*) AS count FROM projects", conn)['count'][0]
            total_queries = pd.read_sql_query("SELECT COUNT(*) AS count FROM queries", conn)['count'][0]
            feedback_df = pd.read_sql_query("SELECT feedback_rating FROM queries WHERE feedback_rating IS NOT NULL", conn)
            conn.close()
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Students", total_users)
            with col2:
                st.metric("Total Projects", total_projects)
            with col3:
                st.metric("❓ Total Queries", total_queries)
            if not feedback_df.empty:
                avg_rating = round(feedback_df['feedback_rating'].mean(), 2)
                st.info(f"⭐ Average Feedback Rating: {avg_rating}/5")
            else:
                st.info("No feedback submitted yet.")
        except sqlite3.Error as e:
            logger.error(f"Database error in stats: {str(e)}")
            st.error("Failed to load statistics.")
        st.markdown("---", unsafe_allow_html=True)

        # Student Mapping Upload
        st.subheader("Upload Student Mapping")
        uploaded_file = st.file_uploader("Upload a CSV file (student_id,project_title)", type=["csv"], key="mapping_uploader")
        if uploaded_file is not None:
            try:
                mapping_df = pd.read_csv(uploaded_file)
                required_columns = ["student_id", "project_title"]
                if not all(col in mapping_df.columns for col in required_columns):
                    st.error("CSV must contain 'student_id' and 'project_title' columns.")
                elif mapping_df.empty:
                    st.error("CSV is empty.")
                elif mapping_df['student_id'].isnull().any() or mapping_df['project_title'].isnull().any():
                    st.error("CSV contains missing values in 'student_id' or 'project_title'.")
                else:
                    st.markdown("**Preview of Uploaded Student Mapping:**")
                    st.dataframe(mapping_df)
                    if st.button("Save Mapping"):
                        conn = sqlite3.connect(DB_PATH)
                        c = conn.cursor()
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        try:
                            for _, row in mapping_df.iterrows():
                                if not is_valid_email(row['student_id']):
                                    st.error(f"Invalid email format: {row['student_id']}")
                                    continue
                                project_id = str(uuid.uuid4())
                                c.execute('INSERT INTO projects (project_id, email, project_title, timestamp) VALUES (?, ?, ?, ?)',
                                         (project_id, row['student_id'], row['project_title'], timestamp))
                                c.execute('INSERT INTO student_project_map (student_id, project_id, timestamp) VALUES (?, ?, ?)',
                                         (row['student_id'], project_id, timestamp))
                            conn.commit()
                            st.success("Student mapping saved successfully!")
                        except sqlite3.Error as e:
                            st.error(f"Database error: {str(e)}")
                        finally:
                            conn.close()
            except pd.errors.EmptyDataError:
                st.error("CSV is empty or malformed.")
            except pd.errors.ParserError:
                st.error("Error parsing CSV. Ensure proper format.")
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")
        st.markdown("---", unsafe_allow_html=True)

        # Export Query Logs
        st.subheader("Export Query Logs")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Export All to CSV"):
                csv_data, message = export_query_logs_to_csv()
                if csv_data:
                    st.download_button(
                        label="Download All Query Logs CSV",
                        data=csv_data,
                        file_name=f"query_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}_all.csv",
                        mime="text/csv"
                    )
                    st.success(message)
                else:
                    st.error(message)
        with col2:
            if REPORTLAB_AVAILABLE:
                if st.button("Export All to PDF"):
                    pdf_data, message = export_query_logs_to_pdf()
                    if pdf_data:
                        st.download_button(
                            label="Download All Query Logs PDF",
                            data=pdf_data,
                            file_name=f"query_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}_all.pdf",
                            mime="application/pdf"
                        )
                        st.success(message)
                    else:
                        st.error(message)
            else:
                st.warning("PDF export is unavailable.")
        st.markdown("---", unsafe_allow_html=True)

        # Student-wise Query Logs
        st.subheader("Export Student-Wise Query Logs")
        conn = sqlite3.connect(DB_PATH)
        users = get_unique_students(conn)
        conn.close()
        if users:
            selected_student = st.selectbox("Select Student", [email for email, _ in users],
                                           format_func=lambda x: f"{x} ({[name for email, name in users if email == x][0]})")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Export Student CSV"):
                    csv_data, message = export_query_logs_to_csv(student_email=selected_student)
                    if csv_data:
                        st.download_button(
                            label=f"Download {selected_student} Query Logs CSV",
                            data=csv_data,
                            file_name=f"query_logs_{selected_student}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                            mime="text/csv"
                        )
                        st.success(message)
                    else:
                        st.error(message)
            with col2:
                if REPORTLAB_AVAILABLE:
                    if st.button("Export Student PDF"):
                        pdf_data, message = export_query_logs_to_pdf(student_email=selected_student)
                        if pdf_data:
                            st.download_button(
                                label=f"Download {selected_student} Query Logs PDF",
                                data=pdf_data,
                                file_name=f"query_logs_{selected_student}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                mime="application/pdf"
                            )
                            st.success(message)
                        else:
                            st.error(message)
                else:
                    st.warning("PDF export is unavailable.")
        else:
            st.markdown("<p style='font-family: \"Roboto\", sans-serif;'>No students registered.</p>", unsafe_allow_html=True)
        st.markdown("---", unsafe_allow_html=True)

        # Project-Wise Query Logs
        st.subheader("Project-Wise Query Logs")
        conn = sqlite3.connect(DB_PATH)
        query_logs = pd.read_sql_query("SELECT email, name, project_title, question, response, timestamp, feedback_rating FROM queries", conn)
        conn.close()
        if not query_logs.empty:
            project_titles = ["All Projects"] + sorted(query_logs['project_title'].unique().tolist())
            selected_project = st.selectbox("Filter by Project", project_titles)
            filtered_logs = query_logs if selected_project == "All Projects" else query_logs[query_logs['project_title'] == selected_project]
            for project_title in filtered_logs['project_title'].unique():
                with st.expander(f"Project: {project_title}"):
                    project_logs = filtered_logs[filtered_logs['project_title'] == project_title]
                    for _, row in project_logs.iterrows():
                        rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
                        initials = ''.join(word[0].upper() for word in row['name'].split()[:2])
                        st.markdown(
                            f"<div class='history-entry'><span class='avatar'>{initials}</span><strong>{row['name']} ({row['email']}) asked:</strong> {row['question']} <i>(at {format_timestamp(row['timestamp'])})</i><br><strong>Ky’ra replied:</strong> {row['response']}<br><strong>Rating:</strong> {rating}</div>",
                            unsafe_allow_html=True
                        )
                        st.markdown("---")
        else:
            st.markdown("<p style='font-family: \"Roboto\", sans-serif;'>No query logs available.</p>", unsafe_allow_html=True)
        st.markdown("---", unsafe_allow_html=True)

    # Student Dashboard
    def show_student_dashboard(name):
        st.markdown(f"<h1 style='text-align: center; color: #4fb8ac; font-family: \"Roboto\", sans-serif;'>👋 Welcome, {name}!</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; font-family: \"Roboto\", sans-serif;'>Ask Ky’ra about resumes, interviews, or projects!</p>", unsafe_allow_html=True)

        # Project Submission
        st.subheader("Submit Your Project Title")
        project_title = st.text_input("Enter your project title:", placeholder="E.g., AI-based Chatbot")
        if st.button("Submit Project"):
            if project_title:
                success, message = save_project(st.session_state.email, project_title)
                if success:
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.error("Please enter a project title.")
        st.markdown("---", unsafe_allow_html=True)

        # Export Student Query Logs
        st.subheader("Export Your Query Logs")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Export to CSV"):
                csv_data, message = export_query_logs_to_csv(student_email=st.session_state.email)
                if csv_data:
                    st.download_button(
                        label="Download Your Query Logs CSV",
                        data=csv_data,
                        file_name=f"query_logs_{st.session_state.email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        mime="text/csv"
                    )
                    st.success(message)
                else:
                    st.error(message)
        with col2:
            if REPORTLAB_AVAILABLE:
                if st.button("Export to PDF"):
                    pdf_data, message = export_query_logs_to_pdf(student_email=st.session_state.email)
                    if pdf_data:
                        st.download_button(
                            label="Download Your Query Logs PDF",
                            data=pdf_data,
                            file_name=f"query_logs_{st.session_state.email}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                            mime="application/pdf"
                        )
                        st.success(message)
                    else:
                        st.error(message)
            else:
                st.warning("PDF export is unavailable.")
        st.markdown("---", unsafe_allow_html=True)

    # Show dashboard based on role
    if st.session_state.role == "admin":
        show_admin_dashboard(st.session_state.name)
    else:
        show_student_dashboard(st.session_state.name)

    # Query Section
    st.subheader("Ask Ky’ra a Question")
    sample_questions = [
        "How do I write my internship resume?",
        "What are the best final-year projects in AI?",
        "How can I prepare for my interview?",
        "What skills for a cybersecurity career?"
    ]
    selected_question = st.selectbox("Choose a sample question or type your own:", sample_questions + ["Custom question..."])
    query_text = st.text_area("Your Question", value=selected_question if selected_question != "Custom question..." else "", height=150, placeholder="E.g., How to prepare for an internship interview?")

    # Ky’ra API Call
    from ratelimit import limits, sleep_and_retry
    @sleep_and_retry
    @limits(calls=CALLS, period=PERIOD)
    def kyra_response(email, query):
        api_url = "http://kyra.kyras.in:8000/student-query"
        payload = {"student_id": email.strip(), "query": query.strip()}
        retries = 3
        for attempt in range(retries):
            try:
                response = requests.post(api_url, params=payload, timeout=10)
                if response.status_code == 200:
                    return response.json().get("response", "No response from Ky’ra.")
                else:
                    logger.warning(f"API query failed (attempt {attempt + 1}/{retries}): {response.status_code}")
                if attempt < retries - 1:
                    time.sleep(1)
            except requests.exceptions.RequestException as e:
                logger.warning(f"API query failed (attempt {attempt + 1}/{retries}): {str(e)}")
                if attempt < retries - 1:
                    time.sleep(1)
        st.error("Unable to connect to Ky’ra’s API. Try again later.")
        return "Error: API unavailable."

    # Submit Query
    st.markdown('<div class="submit-button">', unsafe_allow_html=True)
    if st.button("Submit", type="primary"):
        if not query_text:
            st.error("Please enter a query.")
        else:
            try:
                conn = sqlite3.connect(DB_PATH)
                response = kyra_response(st.session_state.email, query_text)
                save_query(st.session_state.email, st.session_state.name, query_text, response, conn)
                conn.close()
                st.session_state.chat_history.append({
                    "email": st.session_state.email,
                    "name": st.session_state.name,
                    "query": query_text,
                    "response": response,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                st.success("Query submitted successfully!")
                with st.expander("🧠 Ky’ra’s Response", expanded=True):
                    initials = ''.join(word[0].upper() for word in st.session_state.name.split()[:2])
                    st.markdown(
                        f"<div class='history-entry'><span class='avatar'>{initials}</span><strong>Ky’ra’s Response:</strong> <br>{response}</br></div>",
                        unsafe_allow_html=True
                    )
                    feedback_rating = st.slider("Feedback Rating", min_value=1, max_value=5, value=3, step=1, key=f"rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                    if st.button("Submit Rating", key=f"submit_rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
                        if st.checkbox("Confirm rating", key=f"confirm_rating_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
                            conn = sqlite3.connect(DB_PATH)
                            c = conn.cursor()
                            c.execute('UPDATE queries SET feedback_rating = ? WHERE email = ? AND timestamp = ?',
                                     (feedback_rating, st.session_state.email, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                            conn.commit()
                            conn.close()
                            st.success("Feedback submitted!")
                        else:
                            st.warning("Please confirm the rating submission.")
            except Exception as e:
                st.error(f"Failed to process query: {str(e)}")
    st.markdown('</div>', unsafe_allow_html=True)
    st.markdown("---", unsafe_allow_html=True)

    # Query History
    st.subheader("Your Query History")
    try:
        conn = sqlite3.connect(DB_PATH)
        user_df = pd.read_sql_query("SELECT name, question, response, timestamp, feedback_rating FROM queries WHERE email = ? ORDER BY timestamp DESC",
                                   conn, params=(st.session_state.email,))
        conn.close()

        if not user_df.empty:
            user_df = user_df.drop_duplicates(subset=['question', 'timestamp'])
            items_per_page = 5
            total_pages = (len(user_df) + items_per_page - 1) // items_per_page
            st.session_state.page = max(1, min(st.session_state.page, total_pages))

            start_idx = (st.session_state.page - 1) * items_per_page
            end_idx = start_idx + items_per_page
            paginated_df = user_df.iloc[start_idx:end_idx]

            st.markdown('<div class="chat-container">', unsafe_allow_html=True)
            for _, row in paginated_df.iterrows():
                response_text = row['response'] if pd.notna(row['response']) else "No response available."
                rating = row['feedback_rating'] if pd.notna(row['feedback_rating']) else "Not rated"
                initials = ''.join(word[0].upper() for word in row['name'].split()[:2])
                with st.expander(f"Question at {format_timestamp(row['timestamp'])}"):
                    st.markdown(
                        f"<div class='history-entry'><span class='avatar'>{initials}</span><strong>You asked:</strong> {row['question']} <i>(at {format_timestamp(row['timestamp'])})</i><br><strong>Ky’ra replied:</strong> {response_text}<br><strong>Rating:</strong> {rating}</div>",
                        unsafe_allow_html=True
                    )
                    st.markdown("---")
            st.markdown('</div>', unsafe_allow_html=True)

            col1, col2, col3 = st.columns([1, 2, 1])
            with col1:
                if st.button("Previous", disabled=st.session_state.page == 1):
                    st.session_state.page -= 1
            with col2:
                st.write(f"Page {st.session_state.page} of {total_pages}")
            with col3:
                if st.button("Next", disabled=st.session_state.page == total_pages):
                    st.session_state.page += 1
        else:
            st.markdown("<p style='font-family: 'Roboto', sans-serif;'>No query history yet.</p>", unsafe_allow_html=True)
    except sqlite3.Error as e:
        logger.error(f"Database error in query history: {str(e)}")
        st.error("Failed to load query history.")
    st.markdown("---", unsafe_allow_html=True)

    # Project Submissions
    if st.session_state.role != "admin":
        st.subheader("Your Projects")
        user_projects = get_user_projects(st.session_state.email)
        if not user_projects.empty:
            st.markdown('<div class="chat-container">', unsafe_allow_html=True)
            for _, row in user_projects.iterrows():
                st.markdown(
                    f"<div class='history-entry'><strong>Project Title:</strong> {row['project_title']} <i>(at {format_timestamp(row['timestamp'])})</i></div>",
                    unsafe_allow_html=True
                )
                st.markdown("---", unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.markdown("<p style='font-family: 'Roboto', sans-serif;'>No projects submitted.</p>", unsafe_allow_html=True)
        st.markdown("---", unsafe_allow_html=True)

# Footer
st.markdown(
    "<p class='chat-footer'>Ky’ra is here whenever you need. Ask freely. Grow boldly.</p>",
    unsafe_allow_html=True
)
st.markdown("Your query history and project submissions are securely stored.", unsafe_allow_html=True)