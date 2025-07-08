import './App.css';
import Firewall from "./Components/Firewall";
import Compare from './Components/Compare';
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Device_Status from './Components/Devces_Status';
import Device_Status_Generation from './Components/Devices_Status_Generation';
import Home from './Components/Home';
import Navbar from './Components/Nav';
import { useState, useEffect } from 'react';
import Fwform from './Components/Fw_Firewall';
import FirewallForm from './Components/Firewall';
import Fw_Update from './Components/Update_Firewall';
import Main from './Components/Main';
import ObjectChecker from './Components/ObjectChecker'; // Import the new component

function App() {
  return (
    <div className='App'>
      <BrowserRouter>
        <Navbar /> {/* Show the Navbar globally */}
        <Routes>
          <Route 
            path="/Generatefiles" 
            element={
              <Device_Status_Generation
                file2={"Commands File"}
                url={"home_check/"}
                message="Generate"
              />
            } 
          />
          <Route 
            path="/Compare" 
            element={
              <Device_Status 
                file1={"PreCheck File"}
                file2={"PostCheck File"}
                url={"home/"}
                message="Compare"
              />
            } 
          />
          <Route 
            path="/RuleChecking" 
            element={
              <Firewall/>
            } 
          />
          <Route 
            path="/Fw" 
            element={
              <FirewallForm/>
            } 
          />
          <Route 
            path="/Fwform" 
            element={
              <Fwform/>
            } 
          />
          <Route 
            path="/Firewall_update" 
            element={
              <Fw_Update/>
            } 
          />
          <Route 
            path="/main" 
            element={
              <Main/>
            } 
          />
          {/* New Object Checker Route */}
          <Route 
            path="/object-checker" 
            element={
              <ObjectChecker/>
            } 
          />
          <Route path='*' element={<Home />} /> {/* Default Home page route */}
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;