# Backend Authentication Test Cases

## Test Case 1: User Signup
**Endpoint:** POST /signup  
**Input:** name, email, password  
**Expected Result:** User registered successfully  
**Status:** Pass  

## Test Case 2: Duplicate Signup
**Endpoint:** POST /signup  
**Input:** Existing email  
**Expected Result:** 400 - Email already registered  
**Status:** Pass  

## Test Case 3: Login with Valid Credentials
**Endpoint:** POST /login  
**Input:** Correct email and password  
**Expected Result:** accessToken returned  
**Status:** Pass  

## Test Case 4: Login with Invalid Credentials
**Endpoint:** POST /login  
**Input:** Wrong password  
**Expected Result:** 401 - Invalid credentials  
**Status:** Pass  

## Test Case 5: Access Profile with Valid Token
**Endpoint:** POST /profile  
**Header:** Authorization: Bearer <token>  
**Expected Result:** User details returned  
**Status:** Pass  

## Test Case 6: Access Profile without Token
**Endpoint:** POST /profile  
**Expected Result:** 401 Unauthorized  
**Status:** Pass  
