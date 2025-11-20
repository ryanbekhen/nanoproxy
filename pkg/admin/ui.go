package admin

const adminPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NanoProxy - User Management</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        h1 {
            color: white;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }

        .card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            margin-bottom: 20px;
        }

        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }

        .stat-card h3 {
            font-size: 0.9em;
            opacity: 0.9;
            margin-bottom: 10px;
        }

        .stat-card .number {
            font-size: 2.5em;
            font-weight: bold;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #333;
        }

        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 5px;
            font-size: 1em;
            transition: border-color 0.3s;
        }

        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }

        button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 5px;
            font-size: 1em;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }

        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        button:active {
            transform: translateY(0);
        }

        .btn-danger {
            background: linear-gradient(135deg, #f857a6 0%, #ff5858 100%);
        }

        .btn-danger:hover {
            box-shadow: 0 5px 15px rgba(248, 87, 166, 0.4);
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }

        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }

        th {
            background: #f5f5f5;
            font-weight: 600;
            color: #333;
        }

        tr:hover {
            background: #f9f9f9;
        }

        .actions {
            display: flex;
            gap: 10px;
        }

        .message {
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: none;
        }

        .message.success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }

        .message.error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: #999;
        }

        .empty-state svg {
            width: 100px;
            height: 100px;
            margin-bottom: 20px;
            opacity: 0.3;
        }

        @media (max-width: 768px) {
            h1 {
                font-size: 1.8em;
            }

            .card {
                padding: 20px;
            }

            table {
                font-size: 0.9em;
            }

            th, td {
                padding: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 NanoProxy User Management</h1>

        <div class="stats">
            <div class="stat-card">
                <h3>Total Users</h3>
                <div class="number" id="totalUsers">0</div>
            </div>
        </div>

        <div class="card">
            <h2>Add New User</h2>
            <div id="message" class="message"></div>
            <form id="addUserForm">
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit">Add User</button>
            </form>
        </div>

        <div class="card">
            <h2>Users</h2>
            <div id="usersTable"></div>
        </div>
    </div>

    <script>
        let users = [];

        // Show message
        function showMessage(message, type) {
            const messageEl = document.getElementById('message');
            messageEl.textContent = message;
            messageEl.className = 'message ' + type;
            messageEl.style.display = 'block';
            setTimeout(() => {
                messageEl.style.display = 'none';
            }, 5000);
        }

        // Load users
        async function loadUsers() {
            try {
                const response = await fetch('/admin/api/users');
                const data = await response.json();
                users = data.users || [];
                document.getElementById('totalUsers').textContent = data.count;
                renderUsers();
            } catch (error) {
                console.error('Error loading users:', error);
                showMessage('Failed to load users', 'error');
            }
        }

        // Render users table
        function renderUsers() {
            const container = document.getElementById('usersTable');
            
            if (users.length === 0) {
                container.innerHTML = '<div class="empty-state">No users yet. Add your first user above!</div>';
                return;
            }

            let html = '<table><thead><tr><th>Username</th><th>Actions</th></tr></thead><tbody>';
            
            users.forEach(username => {
                html += '<tr>';
                html += '<td>' + escapeHtml(username) + '</td>';
                html += '<td class="actions">';
                html += '<button onclick="changePassword(\'' + escapeHtml(username) + '\')">Change Password</button>';
                html += '<button class="btn-danger" onclick="deleteUser(\'' + escapeHtml(username) + '\')">Delete</button>';
                html += '</td>';
                html += '</tr>';
            });
            
            html += '</tbody></table>';
            container.innerHTML = html;
        }

        // Escape HTML to prevent XSS
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, m => map[m]);
        }

        // Add user
        document.getElementById('addUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;

            try {
                const response = await fetch('/admin/api/users', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ username, password }),
                });

                if (response.ok) {
                    showMessage('User added successfully!', 'success');
                    document.getElementById('addUserForm').reset();
                    loadUsers();
                } else {
                    const error = await response.text();
                    showMessage('Failed to add user: ' + error, 'error');
                }
            } catch (error) {
                console.error('Error adding user:', error);
                showMessage('Failed to add user', 'error');
            }
        });

        // Change password
        async function changePassword(username) {
            const newPassword = prompt('Enter new password for ' + username + ':');
            if (!newPassword) return;

            try {
                const response = await fetch('/admin/api/users/' + encodeURIComponent(username), {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ password: newPassword }),
                });

                if (response.ok) {
                    showMessage('Password updated successfully!', 'success');
                } else {
                    const error = await response.text();
                    showMessage('Failed to update password: ' + error, 'error');
                }
            } catch (error) {
                console.error('Error updating password:', error);
                showMessage('Failed to update password', 'error');
            }
        }

        // Delete user
        async function deleteUser(username) {
            if (!confirm('Are you sure you want to delete user "' + username + '"?')) {
                return;
            }

            try {
                const response = await fetch('/admin/api/users/' + encodeURIComponent(username), {
                    method: 'DELETE',
                });

                if (response.ok) {
                    showMessage('User deleted successfully!', 'success');
                    loadUsers();
                } else {
                    const error = await response.text();
                    showMessage('Failed to delete user: ' + error, 'error');
                }
            } catch (error) {
                console.error('Error deleting user:', error);
                showMessage('Failed to delete user', 'error');
            }
        }

        // Load users on page load
        loadUsers();
    </script>
</body>
</html>
`
