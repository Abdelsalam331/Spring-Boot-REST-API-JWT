package com.example.demo.Controller;

import com.example.demo.Model.Employee;
import com.example.demo.Security.Service.AuthenticationService;
import com.example.demo.Security.Auth.authenticationRequest;
import com.example.demo.Security.Auth.authenticationResponse;
import com.example.demo.Security.Auth.registerRequest;
import com.example.demo.Service.EmployeeService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Primary;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;


import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping(path = "/api/v1/employees/auth")
@RequiredArgsConstructor
@Primary
public class Controller {


    private final EmployeeService employeeService;

    private final AuthenticationService authenticationService;

    @GetMapping("/all")
    public ResponseEntity<List<Employee>> getallEmployees(){
       return ResponseEntity.ok(employeeService.getallEmployees());
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<Employee> getaEmployee(@PathVariable("id") Integer id, Authentication auth) {
        return ResponseEntity.ok(employeeService.getOneEmployee(id));
    }

    @PostMapping("/register")
    public ResponseEntity<authenticationResponse> register(
            @RequestBody registerRequest requset
    ){
        return ResponseEntity.ok(authenticationService.register(requset));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<authenticationResponse> authenticate(
            @RequestBody authenticationRequest requset
    ){
        return ResponseEntity.ok(authenticationService.authenticate(requset));
    }

    @PostMapping("/refresh-token")
    public void refresh(
            HttpServletRequest requset,
            HttpServletResponse response
    ) throws IOException {
        authenticationService.refreshToken(requset,response);
    }

    @DeleteMapping("/delete/{id}")
    public ResponseEntity<Boolean> deleteEmployee (@PathVariable("id") Integer id){
        return ResponseEntity.ok(employeeService.deleteById(id));
    };

    @PutMapping("/update")
    public void updateEmployee(@RequestBody Employee employee){
        employeeService.updateEmployee(employee);
    };

}
