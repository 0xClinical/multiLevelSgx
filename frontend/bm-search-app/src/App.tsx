import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { Container, Nav, Navbar } from 'react-bootstrap';
import BMTester from './components/BMTester';
import BMPlusTester from './components/BMPlusTester';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';

function App() {
  return (
    <Router>
      <div className="App">
        <Navbar bg="dark" variant="dark" expand="lg">
          <Container>
            <Navbar.Brand as={Link} to="/">SGX BM 搜索测试</Navbar.Brand>
            <Navbar.Toggle aria-controls="basic-navbar-nav" />
            <Navbar.Collapse id="basic-navbar-nav">
              <Nav className="me-auto">
                <Nav.Link as={Link} to="/">BM 测试</Nav.Link>
                <Nav.Link as={Link} to="/bm-plus">BM++ 测试</Nav.Link>
              </Nav>
            </Navbar.Collapse>
          </Container>
        </Navbar>

        <Container className="mt-3">
          <Routes>
            <Route path="/" element={<BMTester />} />
            <Route path="/bm-plus" element={<BMPlusTester />} />
          </Routes>
        </Container>

        <footer className="bg-light text-center py-3 mt-5">
          <Container>
            <p>SGX BM 搜索服务测试客户端 © {new Date().getFullYear()}</p>
          </Container>
        </footer>
      </div>
    </Router>
  );
}

export default App;
