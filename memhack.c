#include "stdio.h"
#include "string.h"
#include "unistd.h"
#include "stdlib.h"
#include "sys/types.h"
#include "sys/wait.h"
#include "signal.h"
#include "sys/ptrace.h"
#include "fcntl.h"
#include "sys/stat.h"
#include "regex.h"

#define NONE                   "\033[m"   
#define RED                    "\033[0;32;31m"   
#define LIGHT_RED              "\033[1;31m"   
#define GREEN                  "\033[0;32;32m"   
#define LIGHT_GREEN            "\033[1;32m"   
#define BLUE                   "\033[0;32;34m"   
#define LIGHT_BLUE             "\033[1;34m"   
#define DARY_GRAY              "\033[1;30m"   
#define CYAN                   "\033[0;36m"   
#define LIGHT_CYAN             "\033[1;36m"   
#define PURPLE                 "\033[0;35m"   
#define LIGHT_PURPLE           "\033[1;35m"   
#define BROWN                  "\033[0;33m"   
#define YELLOW                 "\033[1;33m"   
#define LIGHT_GRAY             "\033[0;37m"   
#define WHITE                  "\033[1;37m"

#define MAX_LEN 512
#define MAX_NUM 1024
#define export stdout
#define import stdin
#define base "/proc/"

#define EXIT_ERR(m)\
do\
{\
   perror(m);\
   exit(EXIT_FAILURE);\
}\
while(0)\

typedef enum{false,true}bool;

int dubious_address[MAX_NUM+1];
int address_for_setup[MAX_NUM+1];
int dubious_number;
int number_for_setup;
bool memtracking=false;

void handle(char *input,char *pid);
void memlist();
void mempause(char *pid);
void memresume(char *pid);
void memlookup(char *input,char *pid);
void memsetup(char *input,char *pid);

int main(int argc, char *argv[]) {
  char input[MAX_LEN+1];
  dubious_number=0;
  memset(dubious_address,0,sizeof(dubious_address));
  memset(address_for_setup,0,sizeof(address_for_setup));
  fputs(RED"memhack is on work......\n"NONE,export);
  printf(PURPLE"The functions the memhack possess:\n"NONE);
  printf(WHITE"(1):[pause]-------------pause the game\n"NONE);
  printf(CYAN"(2):[resume]------------resume the game\n"NONE);
  printf(BROWN"(3):[lookup <number>]---find the addresses and store them\n"NONE);
  printf(YELLOW"(4):[setup <number>]----change the value of the target number\n"NONE);
  printf(GREEN"(5):[list]--------------output the present dubious address\n"NONE);
  printf(RED"(6):[exit]--------------quit the memhack\n"NONE);
  for(;;){
    fputs(">>>",export);
    fgets(input,sizeof(input),import);
    int size=strlen(input);
    input[size-1]='\0';   
    if(strcmp(input,"exit")==0){
       printf(RED"quit!\n"NONE);
       break;
    }
    handle(input,argv[1]);
  }
  return 0;
}

void handle(char *input,char *pid){
  if(strcmp(input,"list")==0){
     printf(BROWN"Well list!\n"NONE);
     memlist();
  }else if(strcmp(input,"pause")==0){
     printf(LIGHT_RED"Well,pause!\n"NONE);
     mempause(pid);
  }else if(strcmp(input,"resume")==0){
     printf(GREEN"Well,resume!\n"NONE);
     memresume(pid);
  }else if(strncmp(input,"lookup",6)==0){
     printf(LIGHT_GREEN"Well,lookup!\n"NONE);
     memlookup(input,pid);
  }else if(strncmp(input,"setup",5)==0){
     printf(BLUE"Well,setup!\n"NONE);
     memsetup(input,pid);
  }else{
     printf(LIGHT_BLUE"you look look you!\n"NONE);
  }
}

void memlist(){
  for(int i=0;i<dubious_number;i++)
    printf(YELLOW"0x%08x\n"NONE,address_for_setup[i]);
}

void mempause(char *pid){
  int pid_2048=atoi(pid);
  if(!memtracking){
     if((ptrace(PTRACE_ATTACH,pid_2048,NULL,NULL))!=-1)
        memtracking=true;
     else
        EXIT_ERR("pause error!");
  }   
  else{
     printf(DARY_GRAY"tracked!\n"NONE);
  }
}

void memresume(char *pid){
  int pid_2048=atoi(pid);
  if(memtracking){
      if((ptrace(PTRACE_DETACH,pid_2048,NULL,NULL))!=-1)
        memtracking=false;
      else
        EXIT_ERR("resume error!");
  } 
  else{
    printf(CYAN"paused!\n"NONE);
  }
}

void memlookup(char *input,char *pid){
  int tmpaddr[MAX_NUM+1];
  int tmpnumber=0;

  char *str=strtok(input," ");
  str=strtok(NULL," ");
  int data=atoi(str);

  int pid_2048=atoi(pid);
 
  int addr_begin=0x8048000;
  int addr_end=0x8053000;  
  int8_t mem;  

  char path[MAX_LEN+1],buf[MAX_LEN+1];
  regex_t reg1,reg2;
  regmatch_t matched[1];
  const char *match1="rw-p";
  const char *match2="heap";
  FILE *fp;
  strcpy(path,base);
  strcat(path,pid);
  strcat(path,"/maps");
  if((fp=fopen(path,"r"))==NULL)
    EXIT_ERR("map error!\n");
  regcomp(&reg1,match1,REG_EXTENDED);
  regcomp(&reg2,match2,REG_EXTENDED);
  while(fgets(buf,sizeof(buf),fp)!=NULL){
    if(regexec(&reg2,buf,1,matched,0)==0)
      break;
    if(regexec(&reg1,buf,1,matched,0)==0&&regexec(&reg2,buf,1,matched,0)!=0){
      char begin_s[16],end_s[16];
      int offset=0;
      while(buf[offset]!='-'){
        begin_s[offset]=buf[offset];
        offset++;
      }
      begin_s[offset++]='\0';

      int newstart=offset;
      while(buf[offset]!=' '){
        end_s[offset-newstart]=buf[offset];
        offset++;
      }
      end_s[offset]='\0';

      int baddr_begin,baddr_end;
      sscanf(begin_s,"%x",&baddr_begin);
      sscanf(end_s,"%x",&baddr_end);
      if(addr_begin>baddr_begin)
         addr_begin=baddr_begin;
      if(addr_end<baddr_end)
         addr_end=baddr_end;
    }
  }
  regfree(&reg1);
  regfree(&reg2);
  fclose(fp);
  
  for(int addr=addr_begin;addr<addr_end;addr++){
    mem=ptrace(PTRACE_PEEKDATA,pid_2048,addr,NULL);
    if(mem==data){
       tmpaddr[tmpnumber++]=addr;
    }
  }
  
  if(dubious_number==0&&tmpnumber>0){
     for(int i=0;i<tmpnumber;i++)
        address_for_setup[i]=dubious_address[i]=tmpaddr[i];
     number_for_setup=dubious_number=tmpnumber;
  }

  if(number_for_setup>0&&tmpnumber>0){
     int index=0;
     for(int i=0;i<number_for_setup;i++){
        bool check=false;
        for(int j=0;j<tmpnumber;j++){
           if(dubious_address[i]==tmpaddr[j]){   
             check=true;                   
             address_for_setup[index++]=dubious_address[i];
             break;
           }
        }
        if(!check)
           dubious_number--; 
     }
  }

  for(int i=0;i<dubious_number;i++)
     dubious_address[i]=address_for_setup[i];
  number_for_setup=dubious_number;
 
  switch(dubious_number){
    case 0:printf(LIGHT_CYAN"What a pity!\n"NONE);
           break;
    case 1:printf(PURPLE"Only one address left\n"NONE);
           printf(LIGHT_GRAY"[You can set up the scores]!\n"NONE);
           break;
    default:printf(LIGHT_PURPLE"There are %d addresses left\n"NONE,dubious_number);
           printf(WHITE"Try more times!\n"NONE);
           break;
  }
     
}

void memsetup(char *input,char *pid){
  int pid_2048=atoi(pid);
  char *str=strtok(input," ");
  str=strtok(NULL," ");
  int8_t data=atoi(str);
  if(number_for_setup==1){
    ptrace(PTRACE_POKEDATA,pid_2048,address_for_setup[0],data);
    printf("%d\t The address is:0x%08x\n",data,address_for_setup[0]); 
  }
  else{
    printf(DARY_GRAY"Many dubious address!The permission is denied!\n"NONE);
  }
}







