import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import "./App.css";
import Home from "./Pages/Home"; // Import the Home page component
import { BackgroundBoxesDemo } from "./componenets/backgroundBoxesDemo"; // Import BackgroundBoxesDemo component
import ProtectedRoute from "./componenets/protectedRoute"; // Import the ProtectedRoute component

function App() {
  return (
    <Router>
      <Routes>
        {/* Public route for the login/landing page */}
        <Route path="/" element={<BackgroundBoxesDemo />} />

        {/* Protected route for the home page */}
        <Route
          path="/home"
          element={
            <ProtectedRoute>
              <Home />
            </ProtectedRoute>
          }
        />
      </Routes>
    </Router>
  );
}

export default App;
