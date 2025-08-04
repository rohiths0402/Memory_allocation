#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_NAME_LEN 100
#define MAX_LINE_LEN 200
#define MAX_SUBJECTS 20

typedef struct {
    char *name;
    int marks;
} Subject;

typedef struct {
    char *Name;
    int RollNO;
    Subject *subjects;
    float Total;
    float Average;
} Student;


int isRollNoDuplicate(Student *list, int count, int rollNo) {
    for (int i = 0; i < count; i++) {
        if (list[i].RollNO == rollNo) return 1;
    }
    return 0;
}

int AddStudent(Student *studentList, int *NumberOfStudent, int *SubjectCount, char ***subjectNames) {
    Student *stud = &studentList[*NumberOfStudent];
    stud->Name = (char *)malloc(MAX_NAME_LEN);
    if (!stud->Name) return 0;
    printf("Enter Student Name: ");
    scanf(" %s", stud->Name); 
    printf("Enter Roll Number: ");
    scanf("%d", &stud->RollNO);
    if (isRollNoDuplicate(studentList, *NumberOfStudent, stud->RollNO)) {
        printf("⚠️ Roll number already exists. Try again.\n");
        free(stud->Name);
        return 0;
    }
    if (*NumberOfStudent == 0) {
        printf("Enter number of subjects: ");
        scanf("%d", SubjectCount);
        if (*SubjectCount < 3) {
            printf("Minimum 3 subjects required.\n");
            free(stud->Name);
            return 0;
        }
        *subjectNames = (char **)malloc(sizeof(char *) * (*SubjectCount));
        getchar(); 
        for (int i = 0; i < *SubjectCount; i++) {
            (*subjectNames)[i] = (char *)malloc(MAX_NAME_LEN);
            printf("Enter Subject %d Name: ", i + 1);
            fgets((*subjectNames)[i], MAX_NAME_LEN, stdin);

            size_t len = strlen((*subjectNames)[i]);
            if (len > 0 && (*subjectNames)[i][len - 1] == '\n') {
                (*subjectNames)[i][len - 1] = '\0';
            }
        }
        FILE *fptr = fopen("studentsReport.csv", "w");
        if (!fptr) {
            printf("Error creating file.\n");
            return 0;
        }
        fprintf(fptr, "NAME,ROLL.NO.");
        for (int i = 0; i < *SubjectCount; i++)
            fprintf(fptr, ",%s", (*subjectNames)[i]);
        fprintf(fptr, ",TOTAL,AVERAGE\n");
        fclose(fptr);
    }
    stud->subjects = (Subject *)malloc(sizeof(Subject) * (*SubjectCount));
    stud->Total = 0;
    for (int i = 0; i < *SubjectCount; i++) {
        stud->subjects[i].name = (*subjectNames)[i];
        printf("Enter mark for %s: ", (*subjectNames)[i]);
        scanf("%d", &stud->subjects[i].marks);
        stud->Total += stud->subjects[i].marks;
    }
    stud->Average = (float)stud->Total / (*SubjectCount);
    (*NumberOfStudent)++;
    FILE *fptr = fopen("studentsReport.csv", "a");
    if (!fptr) {
        printf("Error opening file for appending.\n");
        return 0;
    }
    fprintf(fptr, "%s,%d", stud->Name, stud->RollNO);
    for (int i = 0; i < *SubjectCount; i++)
        fprintf(fptr, ",%d", stud->subjects[i].marks);
    fprintf(fptr, ",%d,%.2f\n", stud->Total, stud->Average);
    fclose(fptr);
    printf("Student data appended to 'studentsReport.csv'\n");
    return 1;
}


int DisplayAll(Student *studentList, int NumberOfStudent, int SubjectCount) {
    FILE *fptr = fopen("studentsReport.csv", "r");
    if (fptr == NULL) {
        printf("No students to display.\n");
        return 0;
    }
    char line[MAX_LINE_LEN];
    char *subjectNames[MAX_SUBJECTS];
    SubjectCount = 0;
    if (fgets(line, sizeof(line), fptr)) {
        line[strcspn(line, "\n")] = 0; 
        char *token = strtok(line, ","); 
        token = strtok(NULL, ",");      
        token = strtok(NULL, ",");      

        while (token && strcmp(token, "Total") != 0) {
            subjectNames[SubjectCount++] = strdup(token);
            token = strtok(NULL, ",");
        }
    }
    int studentIndex = 1;
    while (fgets(line, sizeof(line), fptr)) {
        line[strcspn(line, "\n")] = 0;
        Student s;
        s.Name = malloc(MAX_NAME_LEN);
        s.subjects = malloc(sizeof(Subject) * SubjectCount);
        s.Total = 0;
        char *token = strtok(line, ",");
        strcpy(s.Name, token);
        token = strtok(NULL, ",");
        s.RollNO = atoi(token);
        for (int i = 0; i < SubjectCount; i++) {
            token = strtok(NULL, ",");
            s.subjects[i].name = subjectNames[i]; 
            s.subjects[i].marks = atoi(token);
            s.Total += s.subjects[i].marks;
        }
        token = strtok(NULL, ","); 
        token = strtok(NULL, ","); 
        s.Average = atof(token);
        printf("\nStudent %d\n", studentIndex++);
        printf("Name: %s\n", s.Name);
        printf("Roll Number: %d\n", s.RollNO);
        for (int i = 0; i < SubjectCount; i++) {
            printf("%s: %d\n", s.subjects[i].name, s.subjects[i].marks);
        }
        printf("Total: %.2f\n", s.Total);
        printf("Average: %.2f\n", s.Average);
        free(s.Name);
        free(s.subjects);
    }
    for (int i = 0; i < SubjectCount; i++) {
        free(subjectNames[i]);
    }
    fclose(fptr);
    return 1;
}

int ExportFile(Student *studentList, int NumberOfStudent, int SubjectCount, char **subjectNames) {
    char *filename= "studentsReport.csv";
    for (int i = 0; i < NumberOfStudent; i++) {
        sprintf(filename, "%d.csv", studentList[i].RollNO);
        FILE *fp = fopen(filename, "w");
        if (fp == NULL) {
            printf("Error opening file %s for writing.\n", filename);
            continue;
        }
        fprintf(fp, "Name,Roll No");
        for (int j = 0; j < SubjectCount; j++) {
            fprintf(fp, ",%s", subjectNames[j]);
        }
        fprintf(fp, ",Total,Average\n");
        fprintf(fp, "%s,%d", studentList[i].Name, studentList[i].RollNO);
        for (int j = 0; j < SubjectCount; j++) {
            fprintf(fp, ",%d", studentList[i].subjects[j].marks);
        }
        fprintf(fp, ",%.2f,%.2f\n", studentList[i].Total, studentList[i].Average);
        fclose(fp);
        printf("Exported data to '%s'\n", filename);
    }
    return 1;
}


int ClassStats(Student *studentList, int NumberOfStudent) {
    if (NumberOfStudent == 0) {
        printf("No student data for stats.\n");
        return 0;
    }
    float total_avg = 0.0;
    for (int i = 0; i < NumberOfStudent; i++) {
        total_avg += studentList[i].Average;
    }
    printf("\nClass Average Percentage: %.2f\n", total_avg / NumberOfStudent);
    return 1;
}

int FindStudent(Student *studentList, int NumberOfStudent) {
    if (NumberOfStudent == 0) {
        printf("No student data available.\n");
        return 0;
    }
    char query[MAX_NAME_LEN];
    printf("Enter name or roll number to search: ");
    scanf("%s", query);
    int found = 0;
    for (int i = 0; i < NumberOfStudent; i++) {
        if (strcmp(studentList[i].Name, query) == 0 || studentList[i].RollNO == atoi(query)) {
            printf("\nMatch Found:\n");
            printf("Name: %s\n", studentList[i].Name);
            printf("Roll No: %d\n", studentList[i].RollNO);
            for (int j = 0; j < MAX_SUBJECTS && studentList[i].subjects[j].name != NULL; j++) {
                printf("%s: %d\n", studentList[i].subjects[j].name, studentList[i].subjects[j].marks);
            }
            printf("Total: %.2f\n", studentList[i].Total);
            printf("Average: %.2f\n", studentList[i].Average);
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("No matching student found.\n");
    }

    return 1;
}

int main() {
    int NumberOfStudent = 0;
    int SubjectCount;
    char **subjectNames;
    int MaxStudents;

    Student *studentList = (Student *)malloc(sizeof(Student) * MaxStudents);
    int choice;
     do {
        printf("\nMenu:\n");
        printf("1. Add Student\n2. Display All\n3. Export\n4. Class Stats\n5. Find Student \n6. Exit\nEnter Choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: {
                
                printf("Enter the  Number of Students: ");
                scanf("%d", &MaxStudents);
                if (NumberOfStudent  > MaxStudents) {
                    printf("Cannot add more than %d students.\n", MaxStudents);
                    break;
                }
                for (int i = 0; i < MaxStudents; i++) {
                    AddStudent(studentList, &NumberOfStudent, &SubjectCount, &subjectNames);
                }
                break;
            }
            case 2:
                DisplayAll(studentList, NumberOfStudent, SubjectCount);
                break;
            case 3:
                ExportFile(studentList, NumberOfStudent, SubjectCount, subjectNames);
                break;
            case 4:
                ClassStats(studentList, NumberOfStudent);
                break;
            case 5:
                FindStudent(studentList, NumberOfStudent);
                break;
            case 6:
                printf("Exiting program.\n");
                break;
            default:
                printf("Invalid choice.\n");
        }
    } while (choice != 6);
   
    for (int i = 0; i < SubjectCount; i++) {
        free(subjectNames[i]);
    }
    free(subjectNames);
    for (int i = 0; i < NumberOfStudent; i++) {
        free(studentList[i].Name);
        free(studentList[i].subjects);
    }
    free(studentList);
    return 0;
}
