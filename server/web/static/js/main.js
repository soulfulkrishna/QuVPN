/**
 * Main JavaScript file for Post-Quantum VPN Web Interface
 */

// Document ready function using vanilla JS with jQuery fallback
document.addEventListener('DOMContentLoaded', function() {
    console.log('Post-Quantum VPN Web Interface initialized');
    
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize Bootstrap popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Initialize jQuery-dependent features if jQuery is available
    if (typeof jQuery !== 'undefined') {
        // Handle form validation
        handleFormValidation();
        
        // Setup time-ago elements
        updateTimeAgoElements();
        
        // Setup user modal events
        setupUserModal();
    }
});

/**
 * Handle form validation for all forms
 */
function handleFormValidation() {
    // Add was-validated class to forms with required fields
    $('form').on('submit', function(event) {
        if (!this.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
        }
        
        $(this).addClass('was-validated');
    });
    
    // Password confirmation validation
    $('input[type="password"]').on('input', function() {
        const confirmPasswordField = $(this).attr('data-confirm-password');
        
        if (confirmPasswordField) {
            const passwordField = $(this);
            const confirmField = $(confirmPasswordField);
            
            confirmField.on('input', function() {
                if (passwordField.val() !== confirmField.val()) {
                    confirmField[0].setCustomValidity('Passwords do not match');
                } else {
                    confirmField[0].setCustomValidity('');
                }
            });
        }
    });
}

/**
 * Update all time-ago elements
 */
function updateTimeAgoElements() {
    $('.time-ago').each(function() {
        const timestamp = $(this).data('timestamp');
        if (timestamp) {
            $(this).text(formatTimeAgo(timestamp));
        }
    });
    
    // Update every minute
    setTimeout(updateTimeAgoElements, 60000);
}

/**
 * Format a timestamp as a human-readable time ago string
 */
function formatTimeAgo(timestamp) {
    const now = Math.floor(Date.now() / 1000);
    const seconds = now - timestamp;
    
    if (seconds < 60) {
        return 'just now';
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        return minutes + ' minute' + (minutes > 1 ? 's' : '') + ' ago';
    } else if (seconds < 86400) {
        const hours = Math.floor(seconds / 3600);
        return hours + ' hour' + (hours > 1 ? 's' : '') + ' ago';
    } else {
        const days = Math.floor(seconds / 86400);
        return days + ' day' + (days > 1 ? 's' : '') + ' ago';
    }
}

/**
 * Format bytes to a human-readable string
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Setup user modal for adding/editing users
 */
function setupUserModal() {
    $('#userModal').on('show.bs.modal', function(event) {
        const button = $(event.relatedTarget);
        const modal = $(this);
        
        // Clear form
        modal.find('form')[0].reset();
        modal.find('form').removeClass('was-validated');
        
        if (button.data('action') === 'edit') {
            const userId = button.data('user-id');
            modal.find('.modal-title').text('Edit User');
            
            // Get user data and fill form
            $.getJSON('/api/users/' + userId, function(user) {
                $('#user-id').val(user.id);
                $('#user-username').val(user.username);
                $('#user-email').val(user.email || '');
                
                // Password is not returned for security reasons
                $('#user-password').attr('placeholder', 'Leave blank to keep current password');
                $('#user-password').removeAttr('required');
                
                $('#user-is-admin').prop('checked', user.is_admin === 1);
                $('#user-is-active').prop('checked', user.is_active === 1);
            });
        } else {
            // Adding a new user
            modal.find('.modal-title').text('Add User');
            $('#user-id').val('');
            $('#user-password').attr('placeholder', 'Enter password').attr('required', 'required');
        }
    });
}

/**
 * Show an alert message
 */
function showAlert(message, type = 'info', timeout = 5000) {
    const alertId = 'alert-' + Date.now();
    const alertHtml = `
        <div id="${alertId}" class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `;
    
    // Add alert to container
    const alertContainer = $('.alert-container');
    if (alertContainer.length) {
        alertContainer.append(alertHtml);
    } else {
        // If no container exists, create one at the top of the page
        $('main').prepend(`<div class="container mt-3 alert-container">${alertHtml}</div>`);
    }
    
    // Auto-dismiss after timeout
    if (timeout > 0) {
        setTimeout(function() {
            $(`#${alertId}`).alert('close');
        }, timeout);
    }
}

/**
 * Handle AJAX errors
 */
$(document).ajaxError(function(event, jqXHR, settings, error) {
    console.error('AJAX Error:', error, jqXHR.responseText);
    
    let errorMessage = 'An error occurred while communicating with the server.';
    
    if (jqXHR.responseJSON && jqXHR.responseJSON.error) {
        errorMessage = jqXHR.responseJSON.error;
    } else if (jqXHR.status === 401) {
        errorMessage = 'Authentication required. Please log in again.';
        // Redirect to login page after a delay
        setTimeout(function() {
            window.location.href = '/login';
        }, 2000);
    } else if (jqXHR.status === 403) {
        errorMessage = 'You do not have permission to perform this action.';
    } else if (jqXHR.status === 404) {
        errorMessage = 'The requested resource was not found.';
    } else if (jqXHR.status === 500) {
        errorMessage = 'Internal server error. Please try again later.';
    }
    
    showAlert(errorMessage, 'danger');
});
