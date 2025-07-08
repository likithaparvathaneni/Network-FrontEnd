import React from "react";
import "../Css/nav.css";
import { Link } from "react-router-dom";

const Navbar = () => {
  return (
    <header className="header">
      <Link to="/" className="logo">
        <img src="Images/Providence-logo.jpg" alt="Logo" className="logo-img" />
        <span className="logo-text"> Providence India </span>
      </Link>
      <nav className="navbar">
        <Link to="/Generatefiles">Generate Files</Link>
        <Link to="/Compare">Compare</Link>
        <Link to="/Fwform">Firewall Finder</Link>
        <Link to="/fw">Rule-Checking</Link>
        {/* New Navigation Item */}
        <Link to="/object-checker">Object Checker</Link>
      </nav>
    </header>
  );
};

export default Navbar;