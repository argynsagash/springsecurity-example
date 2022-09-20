package kz.argynsagash.springsecurityexample.student;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class Student {

    private final Integer studentId;
    private final String studentName;

    public Student(Integer studentId,
                   String studentName) {
        this.studentId = studentId;
        this.studentName = studentName;
    }

    @Override
    public String toString() {
        return "Student{" +
                "studentId=" + studentId +
                ", studentName='" + studentName + '\'' +
                '}';
    }
}