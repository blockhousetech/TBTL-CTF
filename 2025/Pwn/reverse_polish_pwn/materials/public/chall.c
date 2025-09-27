// gcc -o chall chall.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define STACK_MAX 65

typedef struct { 
    int sp;
    int data[STACK_MAX]; 
} Stack;

void msg(const char *msg) {
    fprintf(stderr, "error: %s\n", msg); 
}

int need(Stack *s, int n) {
    if(s->sp < n) {
        msg("stack underflow");
        return 1;
    }
    return 0;
}

int push(Stack *s, int v) {
    if(s->sp > STACK_MAX) {
        msg("stack overflow");
        return 1;
    }
    s->data[s->sp++] = v; 
    return 0;
}

int popv(Stack *s) {
    return s->data[--s->sp];
}

int process_line(char *line) {
    Stack st;
    st.sp = 0;
    char *tok = strtok(line, " \t\r\n");
    static char cmd[32];
    while (tok) {
        strncpy(cmd, tok, 32); 
        cmd[31]=0; 
        if (!strcmp(cmd,"push")) {
            char *num = strtok(NULL, " \t\r\n");
            if (!num) {
                msg("push needs a number");
                return 1;
            }
            char *end;
            long v = strtol(num, &end, 10);
            if (*end) {
                msg("invalid integer");
                return 1;
            }
            if (push(&st, (int)v))
                return 1;
        } else if (!strcmp(cmd,"pop")) {
            if (need(&st,1))
                return 1;
            printf("%d\n", popv(&st));
        } else if (!strcmp(cmd,"add")) {
            if (need(&st,2))
                return 1;
            int b=popv(&st);
            int a=popv(&st); 
            if (push(&st, a+b))
                return 1;
        } else if (!strcmp(cmd,"sub")) {
            if (need(&st,2))
                return 1;
            int b=popv(&st);
            int a=popv(&st);
            if (push(&st, a-b))
                return 1;
        } else if (!strcmp(cmd,"rot")) { // (x1 x2 x3 -- x2 x3 x1)
            if (need(&st,3))
                return 1;
            int x1 = st.data[st.sp-1];
            int x2 = st.data[st.sp];
            int x3 = st.data[st.sp+1];
            st.data[st.sp-1] = x2;
            st.data[st.sp] = x3;
            st.data[st.sp+1] = x1;
        } else if (!strcmp(cmd,"dup")) {
            if (need(&st,1))
                return 1;
            if (push(&st, st.data[st.sp-1]))
                return 1;
        } else {
            msg("unknown command");
            return 1;
        }
        tok = strtok(NULL, " \t\r\n");
    }
    return 0;
}

void rpn_loop() {
    char line[1024];
    printf("RPN> ");
    while (fgets(line, sizeof line, stdin)) {
        if (process_line(line)) {
            return ;
        }
        printf("RPN> ");
    }
}

int main(void){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    char help[] = 
        "RPN calculator commands:\n"
        " push <num>  - push number onto stack\n"
        " pop         - pop number from stack and print it\n"
        " add         - pop two numbers, add them, push result\n"
        " sub         - pop two numbers, subtract second from first, push result\n"
        " dup         - duplicate top stack value\n"
        " rot         - rotate top three stack values\n";
    printf("%s", help);
    rpn_loop();
    printf("Bye\n");
    return 0;
}
