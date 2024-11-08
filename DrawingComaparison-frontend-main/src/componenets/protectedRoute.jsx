import React, { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";

function ProtectedRoute({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(null);

  // In protectedRoute.jsx
  useEffect(() => {
    const checkAuthStatus = async () => {
      try {
        const response = await fetch("http://localhost:5000/@me", {
          method: "GET",
          credentials: "include", // Include cookies with the request
        });

        if (response.ok) {
          setIsAuthenticated(true);
        } else {
          setIsAuthenticated(false);
        }
      } catch (error) {
        console.error("Error checking auth status:", error);
        setIsAuthenticated(false);
      }
    };

    checkAuthStatus();
  }, []);

  // Loading state to avoid rendering children until auth status is checked
  if (isAuthenticated === null) {
    return <div>Loading...</div>;
  }

  // If the user is authenticated, render the children (protected content)
  // Otherwise, redirect to the login page
  return isAuthenticated ? children : <Navigate to="/" replace />;
}

export default ProtectedRoute;
