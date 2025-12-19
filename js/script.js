// Global variables
let currentUser = null;
let authToken = localStorage.getItem('authToken');
let editingVegetableId = null;

// DOM elements
const authSection = document.getElementById('auth-section');
const vegetableSection = document.getElementById('vegetable-section');
const userInfo = document.getElementById('user-info');
const userName = document.getElementById('user-name');
const userProfileBtn = document.getElementById('user-profile-btn');
const logoutBtn = document.getElementById('logout-btn');
const loading = document.getElementById('loading');
const message = document.getElementById('message');

// Authentication elements
const tabBtns = document.querySelectorAll('.tab-btn');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginFormElement = document.getElementById('loginForm');
const registerFormElement = document.getElementById('registerForm');
const forgotPasswordLink = document.getElementById('forgot-password-link');
const forgotPasswordModal = document.getElementById('forgot-password-modal');
const forgotPasswordCloseBtn = document.getElementById('forgot-password-close');
const forgotPasswordRequestForm = document.getElementById('forgot-password-request-form');
const forgotPasswordResetForm = document.getElementById('forgot-password-reset-form');
const forgotStepRequest = document.getElementById('forgot-step-request');
const forgotStepReset = document.getElementById('forgot-step-reset');

// Vegetable elements
const addVegetableBtn = document.getElementById('add-vegetable-btn');
const vegetableModal = document.getElementById('vegetable-modal');
const vegetableForm = document.getElementById('vegetableForm');
const modalTitle = document.getElementById('modal-title');
const closeVegetableModalBtn = document.getElementById('close-vegetable-modal');
const cancelBtn = document.getElementById('cancel-btn');
const vegetablesList = document.getElementById('vegetables-list');

// API base URL - Automatically detects environment
// Works on both GitHub Pages and Hostinger backend server
const getApiBase = () => {
    // Check if API URL is set via data attribute (for manual override)
    const container = document.querySelector('.container') || document.body;
    const dataApiUrl = container.getAttribute('data-api-url');
    if (dataApiUrl) {
        return dataApiUrl;
    }
    
    const hostname = window.location.hostname;
    
    // If running on GitHub Pages, use the Hostinger backend URL
    if (hostname.includes('github.io') || hostname.includes('github.com')) {
        return 'https://vegetable.bytevortexz.com/api';
    }
    
    // If running on the backend server itself (Hostinger), use relative URL
    // This covers: vegetable.bytevortexz.com, localhost, 127.0.0.1, etc.
    return '/api';
};

const API_BASE = getApiBase();

// Configure axios defaults
axios.defaults.baseURL = API_BASE;
axios.defaults.headers.common['Accept'] = 'application/json';
axios.defaults.headers.common['Content-Type'] = 'application/json';

// Add axios interceptor for authentication
axios.interceptors.request.use(config => {
    if (authToken) {
        config.headers.Authorization = `Bearer ${authToken}`;
    }
    // If sending FormData, remove Content-Type to let browser set it with boundary
    if (config.data instanceof FormData) {
        delete config.headers['Content-Type'];
    }
    return config;
});

// Add axios interceptor for handling auth errors
axios.interceptors.response.use(
    response => response,
    error => {
        if (error.response && (error.response.status === 401 || error.response.status === 422)) {
            handleInvalidToken();
        }
        return Promise.reject(error);
    }
);

// Initialize application
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
    setupEventListeners();
});

function initializeApp() {
    console.log('🚀 Initializing Laravel app...');
    
    // First, try to load user data from localStorage
    const storedUser = localStorage.getItem('currentUser');
    const storedToken = localStorage.getItem('authToken');
    
    if (storedUser && storedToken) {
        try {
            currentUser = JSON.parse(storedUser);
            authToken = storedToken;
            console.log('✅ Loaded user data from localStorage:', currentUser.username);
            
            // Check if token is still valid
            checkAuthStatus();
            return;
        } catch (error) {
            console.error('❌ Error parsing stored user:', error);
            localStorage.removeItem('currentUser');
            localStorage.removeItem('authToken');
        }
    }
    
    if (authToken) {
        console.log('🔍 Checking auth status with existing token...');
        checkAuthStatus();
    } else {
        console.log('❌ No valid authentication found, showing auth section');
        showAuthSection();
    }
}

function setupEventListeners() {
    // Tab switching
    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });

    // Form submissions
    if (loginFormElement) {
        loginFormElement.addEventListener('submit', handleLogin);
    }
    if (registerFormElement) {
        registerFormElement.addEventListener('submit', handleRegister);
    }
    if (vegetableForm) {
        vegetableForm.addEventListener('submit', handleVegetableSubmit);
    }

    // Vegetable sort event listener
    const vegetableSort = document.getElementById('vegetable-sort');
    if (vegetableSort) {
        vegetableSort.addEventListener('change', () => {
            displayVegetables(allVegetables);
        });
    }

    // Vegetable seller filter event listener
    const vegetableSellerFilter = document.getElementById('vegetable-seller-filter');
    if (vegetableSellerFilter) {
        vegetableSellerFilter.addEventListener('change', () => {
            displayVegetables(allVegetables);
        });
    }

    // Modal controls
    if (addVegetableBtn) {
        addVegetableBtn.addEventListener('click', () => {
            // Check if seller is approved before opening modal
            if (currentUser && currentUser.role === 'seller' && currentUser.seller_status !== 'approved') {
                showErrorMessage('Your seller account must be approved before you can add products. Please wait for admin approval.');
                return;
            }
            openVegetableModal();
        });
    }
    if (closeVegetableModalBtn) {
        closeVegetableModalBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            closeVegetableModal();
        });
    }
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeVegetableModal);
    }
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
    if (userProfileBtn) {
        userProfileBtn.addEventListener('click', showUserProfile);
    }

    // Admin section event listeners
    const viewSellersBtn = document.getElementById('view-sellers-btn');
    const viewVegetablesBtn = document.getElementById('view-vegetables-btn');
    const sellerSearch = document.getElementById('seller-search');
    const sellerStatusFilter = document.getElementById('seller-status-filter');

    if (viewSellersBtn) {
        viewSellersBtn.addEventListener('click', () => {
            loadSellers();
            document.getElementById('sellers-section').style.display = 'block';
        });
    }

    if (viewVegetablesBtn) {
        viewVegetablesBtn.addEventListener('click', () => {
            showVegetableSection();
            loadVegetables();
        });
    }

    // Admin Dashboard button (to go back to sellers view from vegetables)
    const adminDashboardBtn = document.getElementById('admin-dashboard-btn');
    if (adminDashboardBtn) {
        adminDashboardBtn.addEventListener('click', () => {
            showAdminSection();
        });
        
        // Customer seller browsing
        const browseSellersBtn = document.getElementById('browse-sellers-btn');
        const viewAllProductsBtn = document.getElementById('view-all-products-btn');
        const customerSellerSearch = document.getElementById('customer-seller-search');
        
        if (browseSellersBtn) {
            browseSellersBtn.addEventListener('click', () => {
                showCustomerSellersSection();
            });
        }
        
        // Seller orders button
        const sellerOrdersBtn = document.getElementById('seller-orders-btn');
        if (sellerOrdersBtn) {
            sellerOrdersBtn.addEventListener('click', () => {
                showSellerOrdersSection();
            });
        }
        
        // Back to vegetables button
        const backToVegetablesBtn = document.getElementById('back-to-vegetables-btn');
        if (backToVegetablesBtn) {
            backToVegetablesBtn.addEventListener('click', () => {
                hideSellerOrdersSection();
            });
        }
        
        if (viewAllProductsBtn) {
            viewAllProductsBtn.addEventListener('click', () => {
                showCustomerProductsSection();
            });
        }
        
        if (customerSellerSearch) {
            customerSellerSearch.addEventListener('input', (e) => {
                filterCustomerSellers(e.target.value);
            });
        }
        
        // Cart button
        const cartBtn = document.getElementById('cart-btn');
        if (cartBtn) {
            cartBtn.addEventListener('click', () => {
                loadCart();
                openCartModal();
            });
        }
        
        // Orders button
        const ordersBtn = document.getElementById('orders-btn');
        if (ordersBtn) {
            ordersBtn.addEventListener('click', () => {
                loadOrders();
                openOrdersModal();
            });
        }
        
        // Checkout form
        const checkoutForm = document.getElementById('checkout-form');
        if (checkoutForm) {
            checkoutForm.addEventListener('submit', handleCheckout);
        }
        
        // Quantity modal close button
        const quantityModal = document.getElementById('quantity-modal');
        if (quantityModal) {
            const closeBtn = quantityModal.querySelector('.close');
            if (closeBtn) {
                closeBtn.addEventListener('click', closeQuantityModal);
            }
        }
        
        // Close modals when clicking outside
        window.addEventListener('click', (e) => {
            if (quantityModal && e.target === quantityModal) {
                closeQuantityModal();
            }
        });
    }

    if (sellerSearch) {
        sellerSearch.addEventListener('input', debounce(loadSellers, 500));
    }

    if (sellerStatusFilter) {
        sellerStatusFilter.addEventListener('change', loadSellers);
    }

    // Forgot password (OTP-based)
    if (forgotPasswordLink) {
        forgotPasswordLink.addEventListener('click', (e) => {
            e.preventDefault();
            openForgotPasswordModal();
        });
    }
    if (forgotPasswordCloseBtn) {
        forgotPasswordCloseBtn.addEventListener('click', closeForgotPasswordModal);
    }
    if (forgotPasswordRequestForm) {
        forgotPasswordRequestForm.addEventListener('submit', handleForgotPasswordRequest);
    }
    if (forgotPasswordResetForm) {
        forgotPasswordResetForm.addEventListener('submit', handleForgotPasswordReset);
    }

    // Confirm modal event listeners
    const confirmModal = document.getElementById('confirm-modal');
    const confirmOk = document.getElementById('confirm-ok');
    const confirmCancel = document.getElementById('confirm-cancel');
    
    if (confirmOk) {
        confirmOk.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (confirmCallback) {
                confirmCallback();
            }
            hideConfirmDialog();
        });
    }
    
    if (confirmCancel) {
        confirmCancel.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            hideConfirmDialog();
        });
    }

    // Close modals when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === vegetableModal) {
            closeVegetableModal();
        }
        if (confirmModal && e.target === confirmModal) {
            hideConfirmDialog();
        }
    });
}

// Tab switching
function switchTab(tab) {
    tabBtns.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.tab === tab);
    });

    if (loginForm && registerForm) {
        loginForm.classList.toggle('active', tab === 'login');
        registerForm.classList.toggle('active', tab === 'register');
    }
}

// Authentication functions
async function handleLogin(e) {
    e.preventDefault();
    const submitButton = e.target.querySelector('button[type="submit"]');
    showLoading(submitButton);

    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    try {
        const response = await axios.post('/login', { username, password });
        const data = response.data;

        authToken = data.access_token;
        currentUser = data.user;
        localStorage.setItem('authToken', authToken);
        localStorage.setItem('currentUser', JSON.stringify(data.user));
        showSuccessMessage('Login successful!');
        
        // Show appropriate section based on user role
        if (currentUser.role === 'admin') {
            showAdminSection();
            loadSellers();
        } else {
            showVegetableSection();
            loadVegetables();
        }
    } catch (error) {
        console.error('Login error:', error);
        if (error.response) {
            const data = error.response.data;
            if (error.response.status === 403 && data.error && data.error.type === 'VERIFICATION_ERROR') {
                showErrorMessage(data.error.description || 'Please check your email and click the verification link to complete your login.');
            } else {
                showErrorMessage(data.error?.description || data.error || 'Login failed');
            }
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    } finally {
        hideLoading(submitButton);
    }
}

async function handleRegister(e) {
    e.preventDefault();
    const submitButton = e.target.querySelector('button[type="submit"]');
    showLoading(submitButton);

    const name = document.getElementById('register-name').value;
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const gmail = document.getElementById('register-gmail').value;
    const password = document.getElementById('register-password').value;
    const role = document.querySelector('input[name="register-role"]:checked')?.value || 'customer';

    try {
        const response = await axios.post('/register', { name, username, email, gmail, password, role });
        const data = response.data;

        let message = data.message || 'Registration successful! Please check your email and click the verification link to complete your registration.';
        if (role === 'seller') {
            message += ' Your seller account will be reviewed by an admin for approval.';
        }
        
        showSuccessMessage(message);
        // Clear the form
        document.getElementById('registerForm').reset();
        // Reset role to customer
        document.querySelector('input[name="register-role"][value="customer"]').checked = true;
        // Switch to login tab
        switchTab('login');
    } catch (error) {
        console.error('Registration error:', error);
        if (error.response) {
            const data = error.response.data;
            showErrorMessage(data.error?.description || data.error || 'Registration failed');
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    } finally {
        hideLoading(submitButton);
    }
}

async function handleLogout() {
    try {
        await axios.post('/logout');
    } catch (error) {
        console.error('Logout error:', error);
    } finally {
        // Clear local storage and state regardless of server response
        localStorage.removeItem('authToken');
        localStorage.removeItem('currentUser');
        authToken = null;
        currentUser = null;
        showAuthSection();
        showSuccessMessage('Logged out successfully');
    }
}

function showUserProfile() {
    if (!currentUser) {
        showErrorMessage('No user data available');
        return;
    }
    
    // Update profile modal with user data
    document.getElementById('profile-name').textContent = currentUser.name || 'N/A';
    document.getElementById('profile-username').textContent = currentUser.username || 'N/A';
    document.getElementById('profile-email').textContent = currentUser.email || 'N/A';
    document.getElementById('profile-id').textContent = currentUser.id || 'N/A';
    document.getElementById('profile-verified').textContent = currentUser.email_verified ? 'Yes ✓' : 'No ✗';
    
    // Update avatar - use profile image if available, otherwise use generated avatar
    const avatarImg = document.getElementById('profile-avatar');
    if (currentUser.profile_image) {
        avatarImg.src = currentUser.profile_image;
    } else {
        const userName = encodeURIComponent(currentUser.name || 'User');
        avatarImg.src = `https://ui-avatars.com/api/?name=${userName}&size=120&background=6366f1&color=fff&bold=true`;
    }
    
    // Show the profile modal
    const profileModal = document.getElementById('profile-modal');
    if (profileModal) {
        profileModal.classList.remove('hidden');
        document.body.classList.add('modal-open');
    }
}

async function handleProfileImageUpload(event) {
    console.log('🔵 handleProfileImageUpload called!', event);
    const file = event.target.files[0];
    if (!file) {
        console.log('❌ No file selected');
        return;
    }
    
    console.log('✅ File selected:', file.name, file.type, file.size);
    
    // Validate file size (5MB max)
    if (file.size > 5 * 1024 * 1024) {
        showErrorMessage('Image size must be less than 5MB');
        event.target.value = '';
        return;
    }
    
    // Validate file type
    if (!file.type.match('image.*')) {
        showErrorMessage('Please select a valid image file');
        event.target.value = '';
        return;
    }
    
    showLoading();
    
    try {
        const formData = new FormData();
        formData.append('image', file);
        
        console.log('Uploading profile image...');
        const response = await axios.post('/profile/image', formData);
        console.log('Upload successful:', response.data);
        console.log('Profile image URL received:', response.data.user?.profile_image);
        
        // Update current user data
        currentUser = response.data.user;
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
        
        // Update avatar image
        const avatarImg = document.getElementById('profile-avatar');
        if (avatarImg && currentUser.profile_image) {
            console.log('Setting image src to:', currentUser.profile_image);
            avatarImg.src = currentUser.profile_image;
            // Force image reload if it fails
            avatarImg.onerror = function() {
                console.error('Image failed to load:', this.src);
                // Try to reload after a moment
                setTimeout(() => {
                    this.src = this.src + '?t=' + Date.now();
                }, 1000);
            };
            avatarImg.onload = function() {
                console.log('Image loaded successfully:', this.src);
            };
        }
        
        showSuccessMessage('Profile image updated successfully!');
        
    } catch (error) {
        console.error('Profile image upload error:', error);
        console.error('Error details:', {
            message: error.message,
            response: error.response?.data,
            status: error.response?.status,
            headers: error.response?.headers
        });
        
        if (error.response) {
            const data = error.response.data;
            const errorMsg = data.error?.description || data.message || 'Failed to update profile image';
            showErrorMessage(errorMsg);
        } else if (error.request) {
            showErrorMessage('Network error. Please check your connection and try again.');
        } else {
            showErrorMessage('An error occurred. Please try again.');
        }
    } finally {
        hideLoading();
        // Reset file input
        event.target.value = '';
    }
}

function closeProfileModal() {
    const profileModal = document.getElementById('profile-modal');
    if (profileModal) {
        profileModal.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }
}

// Forgot password modal helpers (OTP-based reset)
function openForgotPasswordModal() {
    if (forgotPasswordModal) {
        // Reset forms and show first step
        if (forgotPasswordRequestForm) {
            forgotPasswordRequestForm.reset();
        }
        if (forgotPasswordResetForm) {
            forgotPasswordResetForm.reset();
        }
        if (forgotStepRequest && forgotStepReset) {
            forgotStepRequest.classList.remove('hidden');
            forgotStepReset.classList.add('hidden');
        }

        forgotPasswordModal.classList.remove('hidden');
        document.body.classList.add('modal-open');
    }
}

function closeForgotPasswordModal() {
    if (forgotPasswordModal) {
        forgotPasswordModal.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }
}

// Forgot password handlers
async function handleForgotPasswordRequest(e) {
    e.preventDefault();
    const submitButton = e.target.querySelector('button[type="submit"]');
    showLoading(submitButton);

    const username = document.getElementById('forgot-username').value.trim();
    const gmail = document.getElementById('forgot-gmail').value.trim();

    try {
        const response = await axios.post('/forgot-password/request', { username, gmail });
        const data = response.data;

        showSuccessMessage(data.message || 'A 6-digit code has been sent to your Gmail.');

        // Pre-fill reset form
        const resetUsername = document.getElementById('forgot-reset-username');
        const resetGmail = document.getElementById('forgot-reset-gmail');
        if (resetUsername) resetUsername.value = username;
        if (resetGmail) resetGmail.value = gmail;

        // Show reset step
        if (forgotStepRequest && forgotStepReset) {
            forgotStepRequest.classList.add('hidden');
            forgotStepReset.classList.remove('hidden');
        }
    } catch (error) {
        console.error('Forgot password request error:', error);
        if (error.response) {
            const data = error.response.data;
            showErrorMessage(data.error?.description || data.error || 'Failed to send reset code');
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    } finally {
        hideLoading(submitButton);
    }
}

async function handleForgotPasswordReset(e) {
    e.preventDefault();
    const submitButton = e.target.querySelector('button[type="submit"]');
    showLoading(submitButton);

    const username = document.getElementById('forgot-reset-username').value.trim();
    const gmail = document.getElementById('forgot-reset-gmail').value.trim();
    const otp = document.getElementById('forgot-otp').value.trim();
    const password = document.getElementById('forgot-new-password').value;
    const passwordConfirm = document.getElementById('forgot-new-password-confirm').value;

    if (password !== passwordConfirm) {
        showErrorMessage('Passwords do not match');
        hideLoading(submitButton);
        return;
    }

    try {
        const response = await axios.post('/forgot-password/reset', {
            username,
            gmail,
            otp,
            password,
            password_confirmation: passwordConfirm,
        });
        const data = response.data;

        showSuccessMessage(data.message || 'Password has been reset. You can now login with your new password.');
        closeForgotPasswordModal();
    } catch (error) {
        console.error('Forgot password reset error:', error);
        if (error.response) {
            const data = error.response.data;
            showErrorMessage(data.error?.description || data.error || 'Failed to reset password');
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    } finally {
        hideLoading(submitButton);
    }
}

// Make functions available globally
window.closeProfileModal = closeProfileModal;

async function checkAuthStatus() {
    try {
        // Check user role from stored data
        const storedUser = JSON.parse(localStorage.getItem('currentUser') || '{}');
        if (storedUser.role === 'admin') {
            await axios.get('/admin/dashboard');
            showAdminSection();
            loadSellers();
        } else {
            await axios.get('/vegetables');
            showVegetableSection();
            loadVegetables();
        }
    } catch (error) {
        console.error('Auth check error:', error);
        console.log('Auth check failed with status:', error.response?.status);
        handleInvalidToken();
    }
}

// Handle invalid token
function handleInvalidToken() {
    console.log('🚨 Invalid or expired token detected');
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
    authToken = null;
    currentUser = null;
    showAuthSection();
    showErrorMessage('Your session has expired. Please login again.');
}

// Fix JWT signature issues by clearing all tokens
function fixJWTSignatureIssue() {
    console.log('🔧 Fixing JWT signature verification issue...');
    localStorage.removeItem('authToken');
    localStorage.removeItem('currentUser');
    authToken = null;
    currentUser = null;
    showAuthSection();
    showSuccessMessage('Authentication cleared! Please login again.');
}

// Make fixJWTSignatureIssue available globally
window.fixJWTSignatureIssue = fixJWTSignatureIssue;

// Debounce function for search
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Admin functions
async function loadSellers() {
    try {
        const search = document.getElementById('seller-search')?.value || '';
        const status = document.getElementById('seller-status-filter')?.value || '';
        
        let url = '/admin/sellers?per_page=50';
        if (search) url += `&search=${encodeURIComponent(search)}`;
        if (status) url += `&seller_status=${encodeURIComponent(status)}`;

        const response = await axios.get(url);
        displaySellers(response.data.data || []);
    } catch (error) {
        console.error('Load sellers error:', error);
        if (error.response && (error.response.status === 401 || error.response.status === 403)) {
            handleInvalidToken();
        } else {
            showErrorMessage('Failed to load sellers');
        }
    }
}

function displaySellers(sellers) {
    const sellersList = document.getElementById('sellers-list');
    if (!sellersList) return;
    
    sellersList.innerHTML = '';

    if (sellers.length === 0) {
        sellersList.innerHTML = '<p style="text-align: center; color: #718096; padding: 20px;">No sellers found.</p>';
        return;
    }

    sellers.forEach(seller => {
        const card = document.createElement('div');
        card.className = 'vegetable-card';
        card.style.maxWidth = '100%';
        
        const statusColor = {
            'pending': '#f59e0b',
            'approved': '#10b981',
            'rejected': '#ef4444',
            'suspended': '#6b7280'
        }[seller.seller_status] || '#6b7280';

        const statusBadge = seller.seller_status 
            ? `<span style="display: inline-block; padding: 4px 12px; background: ${statusColor}; color: white; border-radius: 12px; font-size: 12px; font-weight: 600; text-transform: capitalize;">${seller.seller_status}</span>`
            : '';

        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
                <div>
                    <h3 style="margin: 0 0 5px 0;">${seller.name}</h3>
                    <p style="margin: 0; color: #6b7280; font-size: 14px;">@${seller.username}</p>
                </div>
                ${statusBadge}
            </div>
            <div style="margin-bottom: 15px;">
                <p style="margin: 5px 0; color: #374151;"><strong>Email:</strong> ${seller.email}</p>
                <p style="margin: 5px 0; color: #374151;"><strong>Gmail:</strong> ${seller.gmail || 'N/A'}</p>
                <p style="margin: 5px 0; color: #374151;"><strong>Email Verified:</strong> ${seller.email_verified ? '✓ Yes' : '✗ No'}</p>
            </div>
            <div style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin-bottom: 15px;">
                <h4 style="margin: 0 0 10px 0; font-size: 14px; color: #374151;">Statistics</h4>
                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px;">
                    <div>
                        <div style="font-size: 24px; font-weight: bold; color: #6366f1;">${seller.stats.products_count || 0}</div>
                        <div style="font-size: 12px; color: #6b7280;">Products</div>
                    </div>
                    <div>
                        <div style="font-size: 24px; font-weight: bold; color: #10b981;">${seller.stats.orders_count || 0}</div>
                        <div style="font-size: 12px; color: #6b7280;">Orders</div>
                    </div>
                    <div>
                        <div style="font-size: 24px; font-weight: bold; color: #f59e0b;">₱${parseFloat(seller.stats.total_revenue || 0).toFixed(2)}</div>
                        <div style="font-size: 12px; color: #6b7280;">Revenue</div>
                    </div>
                </div>
            </div>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                ${seller.seller_status === 'pending' ? `
                    <button class="btn btn-success" onclick="approveSeller(${seller.id})" style="flex: 1; min-width: 100px;">Approve</button>
                    <button class="btn btn-danger" onclick="rejectSeller(${seller.id})" style="flex: 1; min-width: 100px;">Reject</button>
                ` : ''}
                ${seller.seller_status === 'approved' ? `
                    <button class="btn btn-warning" onclick="suspendSeller(${seller.id})" style="flex: 1; min-width: 100px;">Suspend</button>
                ` : ''}
                ${seller.seller_status === 'suspended' ? `
                    <button class="btn btn-success" onclick="approveSeller(${seller.id})" style="flex: 1; min-width: 100px;">Reactivate</button>
                ` : ''}
            </div>
            <div style="margin-top: 10px; font-size: 12px; color: #9ca3af;">
                Joined: ${new Date(seller.created_at).toLocaleDateString()}
            </div>
        `;
        sellersList.appendChild(card);
    });
}

async function approveSeller(sellerId) {
    showConfirmDialog(
        'Approve Seller',
        'Are you sure you want to approve this seller?',
        async () => {
            try {
                await axios.post(`/admin/users/${sellerId}/approve-seller`);
                showSuccessMessage('Seller approved successfully!');
                loadSellers();
            } catch (error) {
                console.error('Approve seller error:', error);
                showErrorMessage(error.response?.data?.error?.description || 'Failed to approve seller');
            }
        },
        'Approve',
        'Cancel',
        false
    );
}

async function rejectSeller(sellerId) {
    showConfirmDialog(
        'Reject Seller',
        'Are you sure you want to reject this seller? This action cannot be undone.',
        async () => {
            try {
                await axios.post(`/admin/users/${sellerId}/reject-seller`);
                showSuccessMessage('Seller rejected successfully!');
                loadSellers();
            } catch (error) {
                console.error('Reject seller error:', error);
                showErrorMessage(error.response?.data?.error?.description || 'Failed to reject seller');
            }
        },
        'Reject',
        'Cancel',
        true
    );
}

async function suspendSeller(sellerId) {
    showConfirmDialog(
        'Suspend Seller',
        'Are you sure you want to suspend this seller? They will not be able to sell products until reactivated.',
        async () => {
            try {
                await axios.post(`/admin/users/${sellerId}/suspend`);
                showSuccessMessage('Seller suspended successfully!');
                loadSellers();
            } catch (error) {
                console.error('Suspend seller error:', error);
                showErrorMessage(error.response?.data?.error?.description || 'Failed to suspend seller');
            }
        },
        'Suspend',
        'Cancel',
        true
    );
}

// Custom confirmation dialog
let confirmCallback = null;

function showConfirmDialog(title, message, onConfirm, confirmText = 'Confirm', cancelText = 'Cancel', danger = false) {
    const modal = document.getElementById('confirm-modal');
    const titleEl = document.getElementById('confirm-title');
    const messageEl = document.getElementById('confirm-message');
    const okBtn = document.getElementById('confirm-ok');
    const cancelBtn = document.getElementById('confirm-cancel');
    
    if (titleEl) titleEl.textContent = title;
    if (messageEl) messageEl.textContent = message;
    if (okBtn) {
        okBtn.textContent = confirmText;
        okBtn.className = danger ? 'btn btn-danger' : 'btn btn-primary';
    }
    if (cancelBtn) cancelBtn.textContent = cancelText;
    
    confirmCallback = onConfirm;
    
    if (modal) {
        modal.classList.remove('hidden');
        document.body.classList.add('modal-open');
    }
}

function hideConfirmDialog() {
    const modal = document.getElementById('confirm-modal');
    if (modal) {
        modal.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }
    confirmCallback = null;
}

// Load sellers for filter dropdown (admin only)
async function loadSellersForFilter() {
    try {
        const response = await axios.get('/admin/sellers?per_page=100');
        const sellers = response.data.data || [];
        const sellerFilter = document.getElementById('vegetable-seller-filter');
        
        if (sellerFilter) {
            // Keep "All Sellers" option and add seller options
            sellerFilter.innerHTML = '<option value="">All Sellers</option>';
            sellers.forEach(seller => {
                const option = document.createElement('option');
                option.value = seller.id;
                option.textContent = `${seller.name} (@${seller.username})`;
                sellerFilter.appendChild(option);
            });
        }
    } catch (error) {
        console.error('Failed to load sellers for filter:', error);
    }
}

// Make functions available globally
window.approveSeller = approveSeller;
window.rejectSeller = rejectSeller;
window.suspendSeller = suspendSeller;

// UI functions
function showAuthSection() {
    // Show auth section
    if (authSection) {
        authSection.classList.remove('hidden');
        authSection.style.display = 'flex';
    }
    // Hide vegetable section
    if (vegetableSection) {
        vegetableSection.classList.add('hidden');
        vegetableSection.style.display = 'none';
    }
    // Hide admin section
    const adminSection = document.getElementById('admin-section');
    if (adminSection) {
        adminSection.classList.add('hidden');
        adminSection.style.display = 'none';
    }
    // Hide user info
    if (userInfo) userInfo.classList.add('hidden');
}

function showVegetableSection() {
    if (authSection) authSection.classList.add('hidden');
    const adminSectionEl = document.getElementById('admin-section');
    if (adminSectionEl) {
        adminSectionEl.classList.add('hidden');
        adminSectionEl.style.display = 'none';
    }
    if (vegetableSection) {
        vegetableSection.classList.remove('hidden');
        vegetableSection.style.display = 'block';
    }
    if (userInfo) userInfo.classList.remove('hidden');
    if (userName) userName.textContent = currentUser?.name || 'User';
    
    // Show Admin Dashboard button if user is admin
    const adminDashboardBtn = document.getElementById('admin-dashboard-btn');
    if (adminDashboardBtn) {
        if (currentUser && currentUser.role === 'admin') {
            adminDashboardBtn.style.display = 'inline-block';
        } else {
            adminDashboardBtn.style.display = 'none';
        }
    }
    
    // Handle "Add New Vegetable" button visibility and state
    const addVegetableBtn = document.getElementById('add-vegetable-btn');
    if (addVegetableBtn && currentUser) {
        // Hide button for customers
        if (currentUser.role === 'customer') {
            addVegetableBtn.style.display = 'none';
        } else {
            addVegetableBtn.style.display = 'inline-block';
            // Handle seller approval status
            if (currentUser.role === 'seller' && currentUser.seller_status !== 'approved') {
                addVegetableBtn.disabled = true;
                addVegetableBtn.title = 'Your seller account must be approved before you can add products';
                addVegetableBtn.style.opacity = '0.6';
                addVegetableBtn.style.cursor = 'not-allowed';
            } else {
                addVegetableBtn.disabled = false;
                addVegetableBtn.title = '';
                addVegetableBtn.style.opacity = '1';
                addVegetableBtn.style.cursor = 'pointer';
            }
        }
    }
    
    // Show/hide seller orders button
    const sellerOrdersBtn = document.getElementById('seller-orders-btn');
    if (sellerOrdersBtn) {
        if (currentUser && currentUser.role === 'seller' && currentUser.seller_status === 'approved') {
            sellerOrdersBtn.style.display = 'inline-block';
        } else {
            sellerOrdersBtn.style.display = 'none';
        }
    }
    
    // Show/hide customer navigation buttons
    const browseSellersBtn = document.getElementById('browse-sellers-btn');
    const viewAllProductsBtn = document.getElementById('view-all-products-btn');
    const customerSellersSection = document.getElementById('customer-sellers-section');
    
    const cartBtn = document.getElementById('cart-btn');
    const ordersBtn = document.getElementById('orders-btn');
    
    if (currentUser && currentUser.role === 'customer') {
        if (browseSellersBtn) browseSellersBtn.style.display = 'inline-block';
        if (viewAllProductsBtn) viewAllProductsBtn.style.display = 'none';
        if (customerSellersSection) customerSellersSection.classList.add('hidden');
        if (cartBtn) cartBtn.style.display = 'inline-block';
        if (ordersBtn) ordersBtn.style.display = 'inline-block';
        loadCart(); // Load cart to update badge count
    } else {
        if (browseSellersBtn) browseSellersBtn.style.display = 'none';
        if (viewAllProductsBtn) viewAllProductsBtn.style.display = 'none';
        if (cartBtn) cartBtn.style.display = 'none';
        if (ordersBtn) ordersBtn.style.display = 'none';
    }
    
    // Show seller filter and sort options for admins
    const vegetableSellerFilter = document.getElementById('vegetable-seller-filter');
    const sellerSortAsc = document.getElementById('seller-sort-option');
    const sellerSortDesc = document.getElementById('seller-sort-desc-option');
    
    if (currentUser && currentUser.role === 'admin') {
        // Show seller sort options
        if (sellerSortAsc) sellerSortAsc.style.display = 'block';
        if (sellerSortDesc) sellerSortDesc.style.display = 'block';
        
        // Show seller filter and load sellers
        if (vegetableSellerFilter) {
            vegetableSellerFilter.style.display = 'block';
            loadSellersForFilter();
        }
    } else {
        // Hide seller options for non-admins
        if (sellerSortAsc) sellerSortAsc.style.display = 'none';
        if (sellerSortDesc) sellerSortDesc.style.display = 'none';
        if (vegetableSellerFilter) vegetableSellerFilter.style.display = 'none';
    }
    
    // Update localStorage with current user info
    if (currentUser) {
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
    }
}

function showAdminSection() {
    // Hide auth section
    if (authSection) {
        authSection.classList.add('hidden');
        authSection.style.display = 'none';
    }
    // Hide vegetable section
    if (vegetableSection) {
        vegetableSection.classList.add('hidden');
        vegetableSection.style.display = 'none';
    }
    // Show admin section
    const adminSection = document.getElementById('admin-section');
    if (adminSection) {
        adminSection.classList.remove('hidden');
        adminSection.style.display = 'block';
        // Make sure sellers section is visible by default
        const sellersSection = document.getElementById('sellers-section');
        if (sellersSection) sellersSection.style.display = 'block';
    }
    // Show user info
    if (userInfo) userInfo.classList.remove('hidden');
    if (userName) userName.textContent = currentUser?.name || 'Admin';
    
    // Update localStorage with current user info
    if (currentUser) {
        localStorage.setItem('currentUser', JSON.stringify(currentUser));
    }
    
    // Load sellers by default
    loadSellers();
}

function showLoading(button = null) {
    // If specific button provided, only handle that one
    const buttons = button ? [button] : document.querySelectorAll('button[type="submit"], button.btn-primary, button.btn-secondary');
    
    buttons.forEach(btn => {
        // Skip if already loading or disabled
        if (btn.disabled || btn.classList.contains('loading-state')) return;
        
        // Save original text and HTML
        const originalText = btn.textContent.trim();
        if (originalText && originalText !== '') {
            btn.setAttribute('data-original-text', originalText);
            btn.disabled = true;
            btn.classList.add('loading-state');
            
            // Create loading spinner HTML
            btn.innerHTML = '<span class="spinner"></span> <span class="loading-text">Loading...</span>';
        }
    });
}

function hideLoading(button = null) {
    // If specific button provided, only handle that one
    const buttons = button ? [button] : document.querySelectorAll('button.loading-state, button[type="submit"]:disabled');
    
    buttons.forEach(btn => {
        btn.disabled = false;
        btn.classList.remove('loading-state');
        
        // Restore original text based on button context
        let originalText = btn.getAttribute('data-original-text');
        
        if (!originalText) {
            // Try to determine from form context
            const form = btn.closest('form');
            if (form) {
                if (form.id === 'loginForm') {
                    originalText = 'Login';
                } else if (form.id === 'registerForm') {
                    originalText = 'Register';
                } else if (form.id === 'vegetableForm') {
                    originalText = 'Save';
                } else if (form.id === 'quantity-form') {
                    originalText = 'Add to Cart';
                } else if (form.id === 'checkout-form') {
                    originalText = 'Place Order';
                } else if (form.id === 'forgot-password-request-form') {
                    originalText = 'Send Code';
                } else if (form.id === 'forgot-password-reset-form') {
                    originalText = 'Reset Password';
                }
            }
        }
        
        // Restore button text
        if (originalText) {
            btn.textContent = originalText;
        } else {
            // Fallback: try to extract from loading text
            const loadingText = btn.querySelector('.loading-text');
            if (loadingText) {
                btn.textContent = btn.textContent.replace('Loading...', '').trim();
            }
        }
        
        // Remove data attribute
        btn.removeAttribute('data-original-text');
    });
}

function showSuccessMessage(message) {
    showToast(message, 'success');
}

function showErrorMessage(message) {
    showToast(message, 'error');
}

function showToast(message, type) {
    // Remove existing toast
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }

    // Create new toast
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);

    // Remove toast after 3 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.remove();
        }
    }, 3000);
}

// Vegetable functions
let allVegetables = []; // Store all vegetables for sorting

async function loadVegetables() {
    try {
        const response = await axios.get('/vegetables');
        allVegetables = response.data;
        displayVegetables(allVegetables);
    } catch (error) {
        console.error('Load vegetables error:', error);
        if (error.response && (error.response.status === 401 || error.response.status === 422)) {
            handleInvalidToken();
        } else {
            showErrorMessage('Failed to load vegetables');
        }
    }
}

function sortVegetables(vegetables, sortOption) {
    const sorted = [...vegetables]; // Create a copy to avoid mutating original array
    
    switch (sortOption) {
        case 'name-asc':
            return sorted.sort((a, b) => a.name.localeCompare(b.name));
        case 'name-desc':
            return sorted.sort((a, b) => b.name.localeCompare(a.name));
        case 'price-asc':
            return sorted.sort((a, b) => parseFloat(a.price) - parseFloat(b.price));
        case 'price-desc':
            return sorted.sort((a, b) => parseFloat(b.price) - parseFloat(a.price));
        case 'seller-asc':
            return sorted.sort((a, b) => {
                const sellerA = a.seller?.name || '';
                const sellerB = b.seller?.name || '';
                return sellerA.localeCompare(sellerB);
            });
        case 'seller-desc':
            return sorted.sort((a, b) => {
                const sellerA = a.seller?.name || '';
                const sellerB = b.seller?.name || '';
                return sellerB.localeCompare(sellerA);
            });
        case 'date-asc':
            return sorted.sort((a, b) => new Date(a.created_at) - new Date(b.created_at));
        case 'date-desc':
        default:
            return sorted.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
    }
}

function displayVegetables(vegetables) {
    if (!vegetablesList) return;
    
    // Get sort option
    const sortSelect = document.getElementById('vegetable-sort');
    const sortOption = sortSelect ? sortSelect.value : 'date-desc';
    
    // Get seller filter
    const sellerFilter = document.getElementById('vegetable-seller-filter');
    const selectedSellerId = sellerFilter ? sellerFilter.value : '';
    
    // Filter by seller if selected
    let filteredVegetables = vegetables;
    if (selectedSellerId && currentUser && currentUser.role === 'admin') {
        filteredVegetables = vegetables.filter(v => v.seller && v.seller.id == selectedSellerId);
    }
    
    // Sort vegetables
    const sortedVegetables = sortVegetables(filteredVegetables, sortOption);
    
    vegetablesList.innerHTML = '';

    if (sortedVegetables.length === 0) {
        vegetablesList.innerHTML = '<p style="text-align: center; color: #718096; grid-column: 1 / -1;">No vegetables found. Add your first vegetable!</p>';
        return;
    }

    sortedVegetables.forEach(vegetable => {
        const card = document.createElement('div');
        card.className = 'vegetable-card';
        
        const imageHtml = vegetable.image 
            ? `<img src="${vegetable.image}" alt="${vegetable.name}" class="vegetable-image">`
            : '<img src="/images/default-vegetable.svg" alt="Default vegetable image" class="vegetable-image default-image">';
        
        // Show seller info for admins
        const sellerInfo = (currentUser && currentUser.role === 'admin' && vegetable.seller) 
            ? `<div style="margin-top: 8px; padding: 8px; background: #f3f4f6; border-radius: 6px; font-size: 12px; color: #6b7280;">
                <strong>Seller:</strong> ${vegetable.seller.name} (@${vegetable.seller.username})
                ${vegetable.seller.seller_status ? `<span style="margin-left: 8px; padding: 2px 8px; background: ${vegetable.seller.seller_status === 'approved' ? '#10b981' : '#f59e0b'}; color: white; border-radius: 12px; font-size: 10px; text-transform: capitalize;">${vegetable.seller.seller_status}</span>` : ''}
               </div>`
            : '';
        
        // Only show Edit/Delete buttons for sellers (their own products) and admins
        const showActions = currentUser && (currentUser.role === 'admin' || 
            (currentUser.role === 'seller' && vegetable.created_by === currentUser.id));
        
        const actionButtons = showActions 
            ? `<div class="vegetable-actions">
                <button class="btn btn-secondary" onclick="editVegetable(${vegetable.id})">Edit</button>
                <button class="btn btn-danger" onclick="deleteVegetable(${vegetable.id})">Delete</button>
               </div>`
            : '';
        
        // Check if product is out of stock
        const stockQuantity = parseFloat(vegetable.stock_quantity) || 0;
        const isOutOfStock = stockQuantity <= 0;
        const stockBadge = isOutOfStock 
            ? '<div style="margin-top: 8px; padding: 6px 12px; background: #ef4444; color: white; border-radius: 6px; font-size: 12px; font-weight: 600; text-align: center; display: inline-block; width: 100%;">Out of Stock</div>'
            : `<div style="margin-top: 8px; padding: 6px 12px; background: #10b981; color: white; border-radius: 6px; font-size: 12px; font-weight: 600; text-align: center; display: inline-block; width: 100%;">In Stock (${stockQuantity.toFixed(2)} kg available)</div>`;
        
        // Add to Cart button for customers (only if in stock)
        const addToCartButton = (currentUser && currentUser.role === 'customer' && !isOutOfStock)
            ? `<div class="vegetable-actions" style="margin-top: 12px;">
                <button class="btn btn-primary" onclick="addToCart(${parseInt(vegetable.id)}, '${String(vegetable.name).replace(/'/g, "\\'")}', ${parseFloat(vegetable.price)})" style="width: 100%;">Add to Cart</button>
               </div>`
            : '';
        
        // Add opacity to out-of-stock cards
        if (isOutOfStock && currentUser && currentUser.role === 'customer') {
            card.style.opacity = '0.7';
        }
        
        card.innerHTML = `
            ${imageHtml}
            <h3>${vegetable.name}</h3>
            <div class="price">₱${parseFloat(vegetable.price).toFixed(2)} <span style="font-size: 0.85em; color: #718096; font-weight: normal;">/kg</span></div>
            <div class="description">${vegetable.description}</div>
            ${stockBadge}
            ${sellerInfo}
            ${addToCartButton}
            ${actionButtons}
        `;
        vegetablesList.appendChild(card);
    });
}

function openVegetableModal(vegetable = null) {
    // If adding new vegetable (not editing), check if seller is approved
    if (!vegetable && currentUser && currentUser.role === 'seller' && currentUser.seller_status !== 'approved') {
        showErrorMessage('Your seller account must be approved before you can add products. Please wait for admin approval.');
        return;
    }
    
    editingVegetableId = vegetable ? vegetable.id : null;
    if (modalTitle) {
        modalTitle.textContent = vegetable ? 'Edit Vegetable' : 'Add New Vegetable';
    }
    
    if (vegetable) {
        document.getElementById('vegetable-name').value = vegetable.name;
        document.getElementById('vegetable-price').value = vegetable.price;
        document.getElementById('vegetable-stock').value = vegetable.stock_quantity ?? 0;
        document.getElementById('vegetable-description').value = vegetable.description;
    } else {
        document.getElementById('vegetableForm').reset();
    }
    
    if (vegetableModal) {
        vegetableModal.classList.remove('hidden');
        document.body.classList.add('modal-open');
    }
}

function closeVegetableModal() {
    if (vegetableModal) {
        vegetableModal.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }
    editingVegetableId = null;
    if (document.getElementById('vegetableForm')) {
        document.getElementById('vegetableForm').reset();
    }
}

async function handleVegetableSubmit(e) {
    e.preventDefault();
    const submitButton = e.target.querySelector('button[type="submit"]');
    showLoading(submitButton);

    const formData = new FormData();
    const name = document.getElementById('vegetable-name').value.trim();
    const price = document.getElementById('vegetable-price').value.trim();
    const stockQuantity = document.getElementById('vegetable-stock').value.trim();
    const description = document.getElementById('vegetable-description').value.trim();
    
    // Validate required fields before sending
    if (!name || !price || stockQuantity === '' || !description) {
        showErrorMessage('Please fill in all required fields (Name, Price, Stock Quantity, Description)');
        hideLoading();
        return;
    }
    
    formData.append('name', name);
    formData.append('price', parseFloat(price)); // Ensure it's a number
    formData.append('stock_quantity', parseFloat(stockQuantity) || 0); // Ensure it's a number (supports decimals)
    formData.append('description', description);
    
    const imageFile = document.getElementById('vegetable-image').files[0];
    if (imageFile) {
        formData.append('image', imageFile);
    }

    try {
        let response;
        if (editingVegetableId) {
            // Use POST with _method=PUT for better FormData support
            formData.append('_method', 'PUT');
            response = await axios.post(`/vegetables/${editingVegetableId}`, formData);
        } else {
            response = await axios.post('/vegetables', formData);
        }

        showSuccessMessage(editingVegetableId ? 'Vegetable updated successfully!' : 'Vegetable added successfully!');
        closeVegetableModal();
        loadVegetables();
    } catch (error) {
        console.error('Vegetable operation error:', error);
        if (error.response) {
            const data = error.response.data;
            if (error.response.status === 401 || error.response.status === 422) {
                handleInvalidToken();
            } else if (error.response.status === 403 && data.error) {
                // Show specific error message for unapproved sellers
                showErrorMessage(data.error.description || 'You are not authorized to perform this action');
            } else if (error.response.status === 400 && data.error) {
                // Show detailed validation errors
                let errorMsg = data.error.description || 'Validation failed';
                if (data.error.errors) {
                    const errorFields = Object.keys(data.error.errors);
                    const firstError = data.error.errors[errorFields[0]][0];
                    errorMsg = `${errorFields[0]}: ${firstError}`;
                }
                showErrorMessage(errorMsg);
            } else {
                showErrorMessage(data.error?.description || data.error || 'Operation failed');
            }
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    } finally {
        hideLoading(submitButton);
    }
}

async function editVegetable(id) {
    try {
        const response = await axios.get(`/vegetables/${id}`);
        openVegetableModal(response.data);
    } catch (error) {
        console.error('Edit vegetable error:', error);
        if (error.response && (error.response.status === 401 || error.response.status === 422)) {
            handleInvalidToken();
        } else {
            showErrorMessage('Failed to load vegetable details');
        }
    }
}

async function deleteVegetable(id) {
    showConfirmDialog(
        'Delete Vegetable',
        'Are you sure you want to delete this vegetable? This action cannot be undone.',
        async () => {
            try {
                await axios.delete(`/vegetables/${id}`);
                showSuccessMessage('Vegetable deleted successfully!');
                loadVegetables();
            } catch (error) {
                console.error('Delete vegetable error:', error);
                if (error.response) {
                    const data = error.response.data;
                    if (error.response.status === 401 || error.response.status === 422) {
                        handleInvalidToken();
                    } else {
                        showErrorMessage(data.error?.description || data.error || 'Failed to delete vegetable');
                    }
                } else {
                    showErrorMessage('Network error. Please try again.');
                }
            }
        },
        'Delete',
        'Cancel',
        true
    );
}

// Customer seller browsing functions
let allCustomerSellers = [];
let currentSellerView = null; // Track if viewing a specific seller's products

async function loadCustomerSellers() {
    // Only customers can load sellers
    if (!currentUser || currentUser.role !== 'customer') {
        showErrorMessage('Only customers can browse sellers.');
        return;
    }
    
    try {
        showLoading();
        const response = await axios.get('/customer/sellers');
        allCustomerSellers = response.data;
        displayCustomerSellers(allCustomerSellers);
        hideLoading();
    } catch (error) {
        console.error('Failed to load sellers:', error);
        hideLoading();
        if (error.response && error.response.status === 401) {
            handleInvalidToken();
        } else if (error.response && error.response.status === 403) {
            showErrorMessage('You do not have permission to browse sellers.');
        } else {
            showErrorMessage('Failed to load sellers. Please try again.');
        }
    }
}

function displayCustomerSellers(sellers) {
    const sellersList = document.getElementById('customer-sellers-list');
    if (!sellersList) return;
    
    sellersList.innerHTML = '';
    
    if (sellers.length === 0) {
        sellersList.innerHTML = '<p style="text-align: center; color: #718096; grid-column: 1 / -1;">No sellers found.</p>';
        return;
    }
    
    sellers.forEach(seller => {
        const card = document.createElement('div');
        card.className = 'seller-card';
        card.style.cssText = 'background: white; border-radius: 12px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;';
        card.onmouseover = () => {
            card.style.transform = 'translateY(-4px)';
            card.style.boxShadow = '0 4px 12px rgba(0,0,0,0.15)';
        };
        card.onmouseout = () => {
            card.style.transform = 'translateY(0)';
            card.style.boxShadow = '0 2px 8px rgba(0,0,0,0.1)';
        };
        card.onclick = () => viewSellerProducts(seller.id);
        
        card.innerHTML = `
            <div style="display: flex; align-items: center; margin-bottom: 15px;">
                <div style="width: 60px; height: 60px; border-radius: 50%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; color: white; font-size: 24px; font-weight: bold; margin-right: 15px;">
                    ${seller.name.charAt(0).toUpperCase()}
                </div>
                <div style="flex: 1;">
                    <h3 style="margin: 0; color: #1a202c; font-size: 18px;">${seller.name}</h3>
                    <p style="margin: 5px 0 0; color: #718096; font-size: 14px;">@${seller.username}</p>
                </div>
            </div>
            <div style="padding-top: 15px; border-top: 1px solid #e2e8f0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="color: #4a5568; font-size: 14px;">Products Available:</span>
                    <span style="color: #667eea; font-weight: 600; font-size: 16px;">${seller.product_count}</span>
                </div>
            </div>
        `;
        
        sellersList.appendChild(card);
    });
}

function filterCustomerSellers(searchTerm) {
    if (!searchTerm.trim()) {
        displayCustomerSellers(allCustomerSellers);
        return;
    }
    
    const filtered = allCustomerSellers.filter(seller => 
        seller.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        seller.username.toLowerCase().includes(searchTerm.toLowerCase())
    );
    
    displayCustomerSellers(filtered);
}

async function viewSellerProducts(sellerId) {
    // Only customers can view seller products
    if (!currentUser || currentUser.role !== 'customer') {
        showErrorMessage('Only customers can view seller products.');
        return;
    }
    
    try {
        showLoading();
        currentSellerView = sellerId;
        const response = await axios.get(`/customer/sellers/${sellerId}/products`);
        const { seller, products } = response.data;
        
        // Update section title
        const sectionTitle = document.getElementById('vegetable-section-title');
        if (sectionTitle) {
            sectionTitle.textContent = `Products from ${seller.name}`;
        }
        
        // Hide sellers section, show products
        const customerSellersSection = document.getElementById('customer-sellers-section');
        if (customerSellersSection) customerSellersSection.classList.add('hidden');
        
        const vegetablesList = document.getElementById('vegetables-list');
        if (vegetablesList) vegetablesList.style.display = 'grid';
        
        // Update navigation buttons
        const browseSellersBtn = document.getElementById('browse-sellers-btn');
        const viewAllProductsBtn = document.getElementById('view-all-products-btn');
        if (browseSellersBtn) browseSellersBtn.style.display = 'inline-block';
        if (viewAllProductsBtn) viewAllProductsBtn.style.display = 'inline-block';
        
        // Display products
        allVegetables = products;
        displayVegetables(products);
        hideLoading();
    } catch (error) {
        console.error('Failed to load seller products:', error);
        hideLoading();
        if (error.response && error.response.status === 401) {
            handleInvalidToken();
        } else {
            showErrorMessage('Failed to load seller products. Please try again.');
        }
    }
}

function showCustomerSellersSection() {
    // Only customers can browse sellers
    if (!currentUser || currentUser.role !== 'customer') {
        showErrorMessage('Only customers can browse sellers.');
        return;
    }
    
    const customerSellersSection = document.getElementById('customer-sellers-section');
    const vegetablesList = document.getElementById('vegetables-list');
    const sectionTitle = document.getElementById('vegetable-section-title');
    const browseSellersBtn = document.getElementById('browse-sellers-btn');
    const viewAllProductsBtn = document.getElementById('view-all-products-btn');
    
    if (customerSellersSection) {
        customerSellersSection.classList.remove('hidden');
    }
    if (vegetablesList) {
        vegetablesList.style.display = 'none';
    }
    if (sectionTitle) {
        sectionTitle.textContent = 'Browse Sellers';
    }
    if (browseSellersBtn) {
        browseSellersBtn.style.display = 'none';
    }
    if (viewAllProductsBtn) {
        viewAllProductsBtn.style.display = 'inline-block';
    }
    
    currentSellerView = null;
    loadCustomerSellers();
}

function showCustomerProductsSection() {
    const customerSellersSection = document.getElementById('customer-sellers-section');
    const vegetablesList = document.getElementById('vegetables-list');
    const sectionTitle = document.getElementById('vegetable-section-title');
    const browseSellersBtn = document.getElementById('browse-sellers-btn');
    const viewAllProductsBtn = document.getElementById('view-all-products-btn');
    
    if (customerSellersSection) {
        customerSellersSection.classList.add('hidden');
    }
    if (vegetablesList) {
        vegetablesList.style.display = 'grid';
    }
    if (sectionTitle) {
        sectionTitle.textContent = 'Vegetable Inventory';
    }
    if (browseSellersBtn) {
        browseSellersBtn.style.display = 'inline-block';
    }
    if (viewAllProductsBtn) {
        viewAllProductsBtn.style.display = 'none';
    }
    
    currentSellerView = null;
    loadVegetables();
}

// Cart functions
let cartData = null;
let pendingAddToCart = { productId: null, productName: null, productPrice: null };

function addToCart(productId, productName, productPrice) {
    // Validate inputs
    const id = parseInt(productId);
    const price = parseFloat(productPrice);
    
    console.log('addToCart called with:', { productId, productName, productPrice, parsedId: id, parsedPrice: price });
    
    if (!id || isNaN(id)) {
        console.error('Invalid product ID:', productId);
        showErrorMessage('Invalid product. Please refresh the page and try again.');
        return;
    }
    
    if (!productName) {
        console.error('Missing product name');
        showErrorMessage('Product information is incomplete. Please try again.');
        return;
    }
    
    if (!price || isNaN(price)) {
        console.error('Invalid product price:', productPrice);
        showErrorMessage('Product price is invalid. Please try again.');
        return;
    }
    
    pendingAddToCart = { 
        productId: id, 
        productName: productName, 
        productPrice: price 
    };
    
    console.log('Stored pendingAddToCart:', pendingAddToCart);
    openQuantityModal(productName, price);
}

function openQuantityModal(productName, productPrice) {
    const quantityModal = document.getElementById('quantity-modal');
    const productNameEl = document.getElementById('quantity-product-name');
    const quantityInput = document.getElementById('quantity-input');
    
    if (quantityModal && productNameEl && quantityInput) {
        productNameEl.textContent = productName;
        quantityInput.value = '1';
        quantityInput.focus();
        quantityModal.classList.remove('hidden');
        document.body.classList.add('modal-open');
        updateQuantityConversion(); // Update conversion display
        updatePriceCalculation(); // Update price calculation
    }
}

function updateQuantityConversion() {
    const quantityInput = document.getElementById('quantity-input');
    const conversionText = document.getElementById('conversion-text');
    
    if (!quantityInput || !conversionText) return;
    
    const kg = parseFloat(quantityInput.value) || 0;
    const grams = Math.round(kg * 1000);
    
    if (kg === 0) {
        conversionText.textContent = '0 kg = 0 grams';
    } else if (kg < 1) {
        conversionText.innerHTML = `<strong>${kg.toFixed(2)} kg</strong> = <strong>${grams} grams</strong>`;
    } else if (kg === 1) {
        conversionText.innerHTML = `<strong>1 kg</strong> = <strong>1,000 grams</strong>`;
    } else {
        conversionText.innerHTML = `<strong>${kg.toFixed(2)} kg</strong> = <strong>${grams.toLocaleString()} grams</strong>`;
    }
    
    // Also update price calculation
    updatePriceCalculation();
}

function updatePriceCalculation() {
    const quantityInput = document.getElementById('quantity-input');
    const priceText = document.getElementById('price-text');
    const priceBreakdown = document.getElementById('price-breakdown');
    
    if (!quantityInput || !priceText || !priceBreakdown || !pendingAddToCart.productPrice) return;
    
    const kg = parseFloat(quantityInput.value) || 0;
    const pricePerKg = pendingAddToCart.productPrice;
    const totalPrice = kg * pricePerKg;
    
    if (kg === 0) {
        priceText.textContent = 'Price: ₱0.00';
        priceBreakdown.textContent = `₱${pricePerKg.toFixed(2)} per kg × 0 kg`;
    } else {
        priceText.innerHTML = `<strong>Total Price: ₱${totalPrice.toFixed(2)}</strong>`;
        priceBreakdown.textContent = `₱${pricePerKg.toFixed(2)} per kg × ${kg.toFixed(2)} kg = ₱${totalPrice.toFixed(2)}`;
    }
}

function closeQuantityModal() {
    const quantityModal = document.getElementById('quantity-modal');
    if (quantityModal) {
        quantityModal.classList.add('hidden');
        document.body.classList.remove('modal-open');
        pendingAddToCart = { productId: null, productName: null, productPrice: null };
    }
}

async function handleQuantitySubmit(e) {
    e.preventDefault();
    const submitButton = e.target.querySelector('button[type="submit"]');
    
    const quantityInput = document.getElementById('quantity-input');
    const quantity = parseFloat(quantityInput.value);
    
    if (!quantity || isNaN(quantity) || quantity <= 0) {
        showErrorMessage('Please enter a valid quantity (greater than 0)');
        return;
    }
    
    if (quantity < 0.01) {
        showErrorMessage('Minimum quantity is 0.01 kg');
        return;
    }
    
    // Validate pendingAddToCart data
    if (!pendingAddToCart || !pendingAddToCart.productId) {
        console.error('Missing product data:', pendingAddToCart);
        showErrorMessage('Product information is missing. Please close this dialog and try adding to cart again.');
        return;
    }
    
    const productId = parseInt(pendingAddToCart.productId);
    const quantityValue = parseFloat(quantity.toFixed(2));
    
    // Debug logging
    console.log('Submitting to cart:', { 
        productId, 
        quantity: quantityValue, 
        pendingAddToCart,
        productIdType: typeof productId,
        productIdIsNaN: isNaN(productId)
    });
    
    if (!productId || isNaN(productId) || productId <= 0) {
        console.error('Invalid product ID:', productId, 'from pendingAddToCart:', pendingAddToCart);
        showErrorMessage('Invalid product ID. Please close this dialog and try adding to cart again.');
        return;
    }
    
    try {
        showLoading(submitButton);
        
        const response = await axios.post('/cart', {
            product_id: productId,
            quantity: quantityValue
        });
        
        // Close modal only after successful response
        closeQuantityModal();
        showSuccessMessage(`${pendingAddToCart.productName} (${quantity} kg) added to cart!`);
        await loadCart(); // Refresh cart to update badge
        hideLoading(submitButton);
    } catch (error) {
        console.error('Add to cart error:', error);
        console.error('Error response:', error.response?.data);
        hideLoading(submitButton);
        if (error.response) {
            const data = error.response.data;
            if (error.response.status === 401) {
                handleInvalidToken();
            } else if (error.response.status === 400) {
                // Handle validation errors
                let errorMsg = 'Validation failed';
                if (data.error) {
                    if (data.error.description) {
                        errorMsg = data.error.description;
                    } else if (data.error.errors) {
                        // Get first validation error
                        const errorFields = Object.keys(data.error.errors);
                        if (errorFields.length > 0) {
                            const firstError = data.error.errors[errorFields[0]];
                            if (Array.isArray(firstError) && firstError.length > 0) {
                                errorMsg = `${errorFields[0]}: ${firstError[0]}`;
                            } else if (typeof firstError === 'string') {
                                errorMsg = `${errorFields[0]}: ${firstError}`;
                            }
                        }
                    }
                }
                showErrorMessage(errorMsg);
            } else {
                showErrorMessage(data.error?.description || data.message || 'Failed to add item to cart');
            }
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    }
}

async function loadCart() {
    if (!currentUser || currentUser.role !== 'customer') return;
    
    try {
        const response = await axios.get('/cart');
        cartData = response.data;
        
        // Update cart badge
        const cartBadge = document.getElementById('cart-count-badge');
        if (cartBadge) {
            if (cartData.item_count > 0) {
                cartBadge.textContent = cartData.item_count;
                cartBadge.style.display = 'block';
            } else {
                cartBadge.style.display = 'none';
            }
        }
        
        // If cart modal is open, update it
        const cartModal = document.getElementById('cart-modal');
        if (cartModal && !cartModal.classList.contains('hidden')) {
            displayCartItems();
        }
    } catch (error) {
        console.error('Load cart error:', error);
        if (error.response && error.response.status === 401) {
            handleInvalidToken();
        }
    }
}

function displayCartItems() {
    const container = document.getElementById('cart-items-container');
    const totalEl = document.getElementById('cart-total');
    const checkoutBtn = document.getElementById('checkout-btn');
    
    if (!container || !cartData) return;
    
    if (cartData.items.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #718096; padding: 40px;">Your cart is empty.</p>';
        if (totalEl) totalEl.textContent = '₱0.00';
        if (checkoutBtn) checkoutBtn.disabled = true;
        return;
    }
    
    container.innerHTML = cartData.items.map(item => {
        const product = item.product;
        return `
            <div style="display: flex; align-items: center; padding: 15px; border-bottom: 1px solid #e2e8f0; gap: 15px;">
                <img src="${product.image || '/images/default-vegetable.svg'}" alt="${product.name}" style="width: 80px; height: 80px; object-fit: cover; border-radius: 8px;">
                <div style="flex: 1;">
                    <h4 style="margin: 0 0 5px; color: #1a202c;">${product.name}</h4>
                    <p style="margin: 0; color: #718096; font-size: 14px;">₱${parseFloat(product.price).toFixed(2)} /kg</p>
                </div>
                <div style="display: flex; flex-direction: column; align-items: center; gap: 5px;">
                    <div style="display: flex; align-items: center; gap: 10px;">
                        <button onclick="updateCartQuantity(${item.id}, ${(parseFloat(item.quantity) - 0.1).toFixed(2)})" style="width: 30px; height: 30px; border: 1px solid #e2e8f0; background: white; border-radius: 4px; cursor: pointer;">-</button>
                        <span style="min-width: 60px; text-align: center; font-weight: 600;">${parseFloat(item.quantity).toFixed(2)} kg</span>
                        <button onclick="updateCartQuantity(${item.id}, ${(parseFloat(item.quantity) + 0.1).toFixed(2)})" style="width: 30px; height: 30px; border: 1px solid #e2e8f0; background: white; border-radius: 4px; cursor: pointer;">+</button>
                    </div>
                    <small style="color: #718096; font-size: 11px;">(${Math.round(parseFloat(item.quantity) * 1000).toLocaleString()} grams)</small>
                </div>
                <div style="text-align: right; min-width: 100px;">
                    <strong style="color: #667eea;">₱${(parseFloat(product.price) * parseFloat(item.quantity)).toFixed(2)}</strong>
                </div>
                <button onclick="removeFromCart(${item.id})" style="background: #ef4444; color: white; border: none; padding: 8px 12px; border-radius: 6px; cursor: pointer; font-size: 12px;">Remove</button>
            </div>
        `;
    }).join('');
    
    if (totalEl) totalEl.textContent = `₱${parseFloat(cartData.total).toFixed(2)}`;
    if (checkoutBtn) checkoutBtn.disabled = false;
}

async function updateCartQuantity(cartId, newQuantity) {
    newQuantity = parseFloat(newQuantity);
    
    if (newQuantity < 0.01) {
        removeFromCart(cartId);
        return;
    }
    
    try {
        showLoading();
        await axios.put(`/cart/${cartId}`, { quantity: newQuantity });
        await loadCart();
        displayCartItems();
        hideLoading();
    } catch (error) {
        console.error('Update cart error:', error);
        hideLoading();
        if (error.response) {
            const data = error.response.data;
            if (error.response.status === 401) {
                handleInvalidToken();
            } else {
                showErrorMessage(data.error?.description || 'Failed to update cart');
            }
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    }
}

async function removeFromCart(cartId) {
    try {
        showLoading();
        await axios.delete(`/cart/${cartId}`);
        await loadCart();
        displayCartItems();
        showSuccessMessage('Item removed from cart');
        hideLoading();
    } catch (error) {
        console.error('Remove from cart error:', error);
        hideLoading();
        if (error.response) {
            const data = error.response.data;
            if (error.response.status === 401) {
                handleInvalidToken();
            } else {
                showErrorMessage(data.error?.description || 'Failed to remove item');
            }
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    }
}

function openCartModal() {
    const cartModal = document.getElementById('cart-modal');
    if (cartModal) {
        displayCartItems();
        cartModal.classList.remove('hidden');
        document.body.classList.add('modal-open');
    }
}

function closeCartModal() {
    const cartModal = document.getElementById('cart-modal');
    if (cartModal) {
        cartModal.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }
}

function openCheckoutModal() {
    if (!cartData || cartData.items.length === 0) {
        showErrorMessage('Your cart is empty');
        return;
    }
    
    const checkoutModal = document.getElementById('checkout-modal');
    const checkoutTotal = document.getElementById('checkout-total');
    
    if (checkoutModal) {
        if (checkoutTotal) checkoutTotal.textContent = `₱${parseFloat(cartData.total).toFixed(2)}`;
        checkoutModal.classList.remove('hidden');
        document.body.classList.add('modal-open');
        closeCartModal(); // Close cart modal
    }
}

function closeCheckoutModal() {
    const checkoutModal = document.getElementById('checkout-modal');
    if (checkoutModal) {
        checkoutModal.classList.add('hidden');
        document.body.classList.remove('modal-open');
        // Reset form
        const form = document.getElementById('checkout-form');
        if (form) form.reset();
    }
}

async function handleCheckout(e) {
    e.preventDefault();
    const submitButton = e.target.querySelector('button[type="submit"]');
    
    const address = document.getElementById('shipping-address').value.trim();
    const city = document.getElementById('shipping-city').value.trim();
    const state = document.getElementById('shipping-state').value.trim();
    const postalCode = document.getElementById('shipping-postal-code').value.trim();
    const country = document.getElementById('shipping-country').value.trim() || 'Philippines';
    const paymentMethod = document.getElementById('payment-method').value;
    const notes = document.getElementById('order-notes').value.trim();
    
    if (!address || !city) {
        showErrorMessage('Please fill in the required address fields');
        return;
    }
    
    try {
        showLoading(submitButton);
        const response = await axios.post('/orders/checkout', {
            shipping_address: address,
            shipping_city: city,
            shipping_state: state || null,
            shipping_postal_code: postalCode || null,
            shipping_country: country,
            payment_method: paymentMethod,
            notes: notes || null
        });
        
        showSuccessMessage('Order placed successfully!');
        closeCheckoutModal();
        await loadCart(); // Refresh cart (should be empty now)
        await loadVegetables(); // Refresh vegetables to show updated stock
        hideLoading(submitButton);
    } catch (error) {
        console.error('Checkout error:', error);
        hideLoading(submitButton);
        if (error.response) {
            const data = error.response.data;
            if (error.response.status === 401) {
                handleInvalidToken();
            } else {
                showErrorMessage(data.error?.description || 'Failed to place order');
            }
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    }
}
// Orders functions
let ordersData = [];

async function loadOrders() {
    if (!currentUser || currentUser.role !== 'customer') return;
    
    try {
        showLoading();
        const response = await axios.get('/orders');
        ordersData = response.data;
        displayOrders(ordersData);
        hideLoading();
    } catch (error) {
        console.error('Load orders error:', error);
        hideLoading();
        if (error.response && error.response.status === 401) {
            handleInvalidToken();
        } else {
            showErrorMessage('Failed to load orders. Please try again.');
        }
    }
}

function displayOrders(orders) {
    const container = document.getElementById('orders-container');
    if (!container) return;
    
    if (orders.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #718096; padding: 40px;">You have no orders yet.</p>';
        return;
    }
    
    container.innerHTML = orders.map(order => {
        const orderDate = new Date(order.created_at).toLocaleDateString('en-US', {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
        
        const statusColors = {
            'pending': '#f59e0b',
            'confirmed': '#3b82f6',
            'processing': '#8b5cf6',
            'shipped': '#6366f1',
            'delivered': '#10b981',
            'cancelled': '#ef4444',
            'refunded': '#6b7280'
        };
        
        const statusColor = statusColors[order.status] || '#6b7280';
        
        return `
            <div style="background: white; border-radius: 12px; padding: 20px; margin-bottom: 15px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); cursor: pointer;" onclick="viewOrderDetails(${order.id})">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
                    <div>
                        <h4 style="margin: 0 0 5px; color: #1a202c;">Order #${order.order_number}</h4>
                        <p style="margin: 0; color: #718096; font-size: 14px;">${orderDate}</p>
                    </div>
                    <div style="text-align: right;">
                        <span style="padding: 6px 12px; background: ${statusColor}; color: white; border-radius: 6px; font-size: 12px; font-weight: 600; text-transform: capitalize;">${order.status}</span>
                        <p style="margin: 10px 0 0; color: #1a202c; font-size: 18px; font-weight: 600;">₱${parseFloat(order.total_amount).toFixed(2)}</p>
                    </div>
                </div>
                <div style="border-top: 1px solid #e2e8f0; padding-top: 15px;">
                    <p style="margin: 0 0 10px; color: #4a5568; font-size: 14px;"><strong>Delivery Address:</strong></p>
                    <p style="margin: 0; color: #718096; font-size: 14px;">${order.shipping_address}, ${order.shipping_city}${order.shipping_state ? ', ' + order.shipping_state : ''}${order.shipping_postal_code ? ' ' + order.shipping_postal_code : ''}</p>
                    <p style="margin: 10px 0 0; color: #718096; font-size: 14px;"><strong>Items:</strong> ${order.items ? order.items.length : 0} item(s)</p>
                </div>
            </div>
        `;
    }).join('');
}

async function viewOrderDetails(orderId) {
    try {
        showLoading();
        const response = await axios.get(`/orders/${orderId}`);
        const order = response.data;
        displayOrderDetails(order);
        openOrderDetailsModal();
        hideLoading();
    } catch (error) {
        console.error('Load order details error:', error);
        hideLoading();
        if (error.response && error.response.status === 401) {
            handleInvalidToken();
        } else {
            showErrorMessage('Failed to load order details. Please try again.');
        }
    }
}

function displayOrderDetails(order) {
    const container = document.getElementById('order-details-container');
    if (!container) return;
    
    const orderDate = new Date(order.created_at).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
    
    const statusColors = {
        'pending': '#f59e0b',
        'confirmed': '#3b82f6',
        'processing': '#8b5cf6',
        'shipped': '#6366f1',
        'delivered': '#10b981',
        'cancelled': '#ef4444',
        'refunded': '#6b7280'
    };
    
    const statusColor = statusColors[order.status] || '#6b7280';
    
    const itemsHtml = order.items ? order.items.map(item => {
        const product = item.product || {};
        return `
            <div style="display: flex; align-items: center; padding: 15px; border-bottom: 1px solid #e2e8f0; gap: 15px;">
                <img src="${product.image || '/images/default-vegetable.svg'}" alt="${product.name}" style="width: 60px; height: 60px; object-fit: cover; border-radius: 8px;">
                <div style="flex: 1;">
                    <h4 style="margin: 0 0 5px; color: #1a202c;">${product.name || 'Product'}</h4>
                    <p style="margin: 0; color: #718096; font-size: 14px;">₱${parseFloat(item.price || 0).toFixed(2)} /kg</p>
                    ${item.seller ? `<p style="margin: 5px 0 0; color: #718096; font-size: 12px;">Seller: ${item.seller.name || item.seller.username}</p>` : ''}
                </div>
                <div style="text-align: right;">
                    <p style="margin: 0; color: #4a5568; font-size: 14px;">${parseFloat(item.quantity || 0).toFixed(2)} kg</p>
                    <p style="margin: 5px 0 0; color: #667eea; font-weight: 600;">₱${parseFloat(item.subtotal || 0).toFixed(2)}</p>
                    <span style="display: inline-block; margin-top: 5px; padding: 4px 8px; background: ${statusColors[item.status] || '#6b7280'}; color: white; border-radius: 4px; font-size: 11px; text-transform: capitalize;">${item.status || 'pending'}</span>
                </div>
            </div>
        `;
    }).join('') : '<p style="text-align: center; color: #718096; padding: 20px;">No items found.</p>';
    
    container.innerHTML = `
        <div style="margin-bottom: 20px;">
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
                <div>
                    <h4 style="margin: 0 0 5px; color: #1a202c;">Order #${order.order_number}</h4>
                    <p style="margin: 0; color: #718096; font-size: 14px;">${orderDate}</p>
                </div>
                <span style="padding: 6px 12px; background: ${statusColor}; color: white; border-radius: 6px; font-size: 12px; font-weight: 600; text-transform: capitalize;">${order.status}</span>
            </div>
        </div>
        
        <div style="background: #f3f4f6; padding: 15px; border-radius: 8px; margin-bottom: 20px;">
            <h5 style="margin: 0 0 10px; color: #1a202c;">Delivery Address</h5>
            <p style="margin: 0; color: #4a5568; font-size: 14px; line-height: 1.6;">
                ${order.shipping_address}<br>
                ${order.shipping_city}${order.shipping_state ? ', ' + order.shipping_state : ''}${order.shipping_postal_code ? ' ' + order.shipping_postal_code : ''}<br>
                ${order.shipping_country || 'Philippines'}
            </p>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h5 style="margin: 0 0 15px; color: #1a202c;">Order Items</h5>
            <div style="background: white; border-radius: 8px; overflow: hidden;">
                ${itemsHtml}
            </div>
        </div>
        
        <div style="border-top: 2px solid #e2e8f0; padding-top: 15px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                <span style="color: #4a5568;">Payment Method:</span>
                <span style="color: #1a202c; font-weight: 600; text-transform: capitalize;">${order.payment_method || 'N/A'}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                <span style="color: #4a5568;">Payment Status:</span>
                <span style="color: #1a202c; font-weight: 600; text-transform: capitalize;">${order.payment_status || 'pending'}</span>
            </div>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 15px; padding-top: 15px; border-top: 1px solid #e2e8f0;">
                <strong style="font-size: 18px; color: #1a202c;">Total Amount:</strong>
                <strong style="font-size: 20px; color: #667eea;">₱${parseFloat(order.total_amount || 0).toFixed(2)}</strong>
            </div>
            ${order.notes ? `<div style="margin-top: 15px; padding: 10px; background: #f3f4f6; border-radius: 6px;"><strong>Notes:</strong> <span style="color: #4a5568;">${order.notes}</span></div>` : ''}
        </div>
        
        <div style="text-align: center; margin-top: 20px;">
            <button class="btn btn-secondary" onclick="closeOrderDetailsModal()">Close</button>
        </div>
    `;
}

function openOrdersModal() {
    const ordersModal = document.getElementById('orders-modal');
    if (ordersModal) {
        ordersModal.classList.remove('hidden');
        document.body.classList.add('modal-open');
    }
}

function closeOrdersModal() {
    const ordersModal = document.getElementById('orders-modal');
    if (ordersModal) {
        ordersModal.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }
}

function openOrderDetailsModal() {
    const orderDetailsModal = document.getElementById('order-details-modal');
    if (orderDetailsModal) {
        orderDetailsModal.classList.remove('hidden');
        document.body.classList.add('modal-open');
    }
}

function closeOrderDetailsModal() {
    const orderDetailsModal = document.getElementById('order-details-modal');
    if (orderDetailsModal) {
        orderDetailsModal.classList.add('hidden');
        document.body.classList.remove('modal-open');
    }
}

// Seller Orders Functions
async function loadSellerOrders() {
    try {
        showLoading();
        const response = await axios.get('/seller/orders/all');
        const orders = response.data;
        displaySellerOrders(orders);
    } catch (error) {
        console.error('Failed to load seller orders:', error);
        if (error.response) {
            const data = error.response.data;
            if (error.response.status === 401) {
                handleInvalidToken();
            } else {
                showErrorMessage(data.error?.description || 'Failed to load orders');
            }
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    } finally {
        hideLoading();
    }
}

function displaySellerOrders(orders) {
    const container = document.getElementById('seller-orders-container');
    if (!container) return;
    
    if (!orders || orders.length === 0) {
        container.innerHTML = '<p style="text-align: center; color: #718096; padding: 40px;">No orders yet.</p>';
        return;
    }
    
    container.innerHTML = orders.map(order => {
        // Filter items to only show this seller's items (backend should already filter, but double-check)
        const sellerItems = order.items.filter(item => {
            return item.seller && item.seller.id === currentUser.id;
        });
        const orderTotal = sellerItems.reduce((sum, item) => sum + (item.subtotal || 0), 0);
        
        const itemsHtml = sellerItems.map(item => {
            const statusColors = {
                'pending': '#f59e0b',
                'processing': '#3b82f6',
                'shipped': '#8b5cf6',
                'delivered': '#10b981',
                'cancelled': '#ef4444'
            };
            const statusColor = statusColors[item.status] || '#718096';
            
            return `
                <div style="padding: 15px; background: #f9fafb; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid ${statusColor};">
                    <div style="display: flex; justify-content: space-between; align-items: start;">
                        <div style="flex: 1;">
                            <h4 style="margin: 0 0 8px 0; color: #1a202c; font-size: 16px;">${item.product ? item.product.name : 'Unknown Product'}</h4>
                            <p style="margin: 4px 0; color: #718096; font-size: 14px;">Quantity: <strong>${parseFloat(item.quantity).toFixed(2)} kg</strong></p>
                            <p style="margin: 4px 0; color: #718096; font-size: 14px;">Price: ₱${parseFloat(item.price).toFixed(2)} per kg</p>
                            ${item.status === 'pending' ? `
                                <button onclick="updateOrderItemStatus(${order.id}, ${item.id}, 'delivered', '${(item.product ? item.product.name : 'Unknown Product').replace(/'/g, "\\'")}')" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px; margin-top: 8px;">
                                    Mark as Delivered
                                </button>
                            ` : ''}
                            <p style="margin: 8px 0 0 0; color: #1a202c; font-weight: 600; font-size: 15px;">Subtotal: ₱${parseFloat(item.subtotal).toFixed(2)}</p>
                        </div>
                        <div style="text-align: right; min-width: 150px;">
                            <div style="margin-bottom: 10px;">
                                <span style="padding: 6px 12px; background: ${statusColor}; color: white; border-radius: 6px; font-size: 12px; font-weight: 600; text-transform: capitalize; display: inline-block;">
                                    ${item.status}
                                </span>
                            </div>
                            ${item.status === 'delivered' ? `
                                <span style="color: #10b981; font-size: 12px; font-weight: 600;">✓ Delivered</span>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
        
        return `
            <div style="background: white; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 2px solid #e2e8f0;">
                    <div>
                        <h3 style="margin: 0 0 5px 0; color: #1a202c;">Order #${order.order_number}</h3>
                        <p style="margin: 5px 0; color: #718096; font-size: 14px;">Customer: ${order.customer ? order.customer.name : 'Unknown'}</p>
                        <p style="margin: 5px 0; color: #718096; font-size: 14px;">Date: ${new Date(order.created_at).toLocaleDateString()}</p>
                    </div>
                    <div style="text-align: right;">
                        <p style="margin: 0; color: #1a202c; font-size: 18px; font-weight: 700;">₱${orderTotal.toFixed(2)}</p>
                    </div>
                </div>
                <div style="margin-bottom: 15px;">
                    <h4 style="margin: 0 0 10px 0; color: #4a5568; font-size: 16px;">Delivery Address:</h4>
                    <p style="margin: 0; color: #718096; font-size: 14px; line-height: 1.6;">
                        ${order.shipping_address}<br>
                        ${order.shipping_city}${order.shipping_state ? ', ' + order.shipping_state : ''} ${order.shipping_postal_code || ''}<br>
                        ${order.shipping_country}
                    </p>
                </div>
                <div>
                    <h4 style="margin: 0 0 10px 0; color: #4a5568; font-size: 16px;">Items:</h4>
                    ${itemsHtml}
                </div>
            </div>
        `;
    }).join('');
}

async function updateOrderItemStatus(orderId, itemId, newStatus, productName = '') {
    try {
        showLoading();
        
        const response = await axios.put(`/seller/orders/${orderId}/items/${itemId}/status`, {
            status: newStatus
        });
        
        const successMessage = productName 
            ? `"${productName}" marked as ${newStatus} successfully!`
            : `Item status updated to ${newStatus} successfully!`;
        showSuccessMessage(successMessage);
        await loadSellerOrders(); // Refresh orders
    } catch (error) {
        console.error('Failed to update order status:', error);
        if (error.response) {
            const data = error.response.data;
            if (error.response.status === 401) {
                handleInvalidToken();
            } else {
                showErrorMessage(data.error?.description || 'Failed to update order status');
            }
        } else {
            showErrorMessage('Network error. Please try again.');
        }
    } finally {
        hideLoading();
    }
}

function showSellerOrdersSection() {
    const sellerOrdersSection = document.getElementById('seller-orders-section');
    const vegetableSection = document.getElementById('vegetable-section');
    
    if (sellerOrdersSection && vegetableSection) {
        vegetableSection.classList.add('hidden');
        sellerOrdersSection.classList.remove('hidden');
        loadSellerOrders();
    }
}

function hideSellerOrdersSection() {
    const sellerOrdersSection = document.getElementById('seller-orders-section');
    const vegetableSection = document.getElementById('vegetable-section');
    
    if (sellerOrdersSection && vegetableSection) {
        sellerOrdersSection.classList.add('hidden');
        vegetableSection.classList.remove('hidden');
    }
}

