# 🧑‍💼 Employee Management System

A simple full-stack Employee Management System built with **PHP**, **MySQL**, **HTML/CSS/JS**. It allows employees to submit leave requests, managers to approve or reject them, and generate reports based on leave data.

---

## 🚀 Features

### 🔐 Authentication
- Secure login system for Employees and Managers
- Session-based authentication
- Logout functionality

### 👩‍💼 Employee Dashboard
- Submit new leave requests (start date, end date, reason)
- View history of leave requests with statuses
- Interactive date validation and clean UI

### 👨‍💼 Manager Dashboard
- View all employee leave requests
- Approve or reject requests directly from dashboard
- Real-time updates on leave statuses

### 📊 Reports
- Summary of all leave requests grouped by status
- Dashboard counts: Approved, Rejected, Pending
- Manager-only access

### 🎨 Frontend Design
- HTML templates with modular separation
- CSS for interactive and responsive styling
- JavaScript for form validation and confirmations

---

## 📂 Folder Structure
employee_management/
│
├── css/
│ └── styles.css # All styles in one place
│
├── js/
│ └── scripts.js # JS for validation and interactions
│
├── templates/
│ ├── login.html
│ ├── employee_dashboard.html
│ ├── manager_dashboard.html
│ └── report.html
│
├── config.php # DB connection
├── login.php # Login logic
├── logout.php # Logout and destroy session
├── employee_dashboard.php # Employee dashboard logic
├── manager_dashboard.php # Manager dashboard logic
├── submit_leave.php # Employee leave submission
├── process_leave.php # Manager approve/reject
├── report.php # Report page for manager

## 🛠️ Technologies Used

- **Frontend:** HTML, CSS, JavaScript
- **Backend:** PHP (vanilla)
- **Database:** MySQL (via XAMPP/phpMyAdmin)
- **Server:** Apache (XAMPP stack)
