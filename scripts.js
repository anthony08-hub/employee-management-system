// scripts.js

function validateLeave() {
  const start = document.getElementById('start_date').value;
  const end = document.getElementById('end_date').value;
  if (start === "" || end === "") {
    alert("Please select both start and end dates");
    return false;
  }
  if (start > end) {
    alert("Start date cannot be after end date");
    return false;
  }
  return true;
}

function confirmAction(action, id) {
  if (confirm(`Are you sure you want to ${action} this leave request?`)) {
    window.location.href = `process_leave.php?action=${action}&id=${id}`;
  }
}
