#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <queue>
#include <list>
#include <ctime>

/*
    Log Analysis

*/

using namespace std;

struct hostValue {
   string ip;
   int val;
};

struct compVal {
  bool operator() (hostValue const & u1, hostValue const & u2) {
                 return u1.val > u2.val;
  }
};

struct winValue {
   int winTime;
   int val;
};

struct wincompVal {
  bool operator() (winValue const & u1, winValue const & u2) {
                 return u1.val > u2.val;
  }
};

char * hostsFileName, *hoursFileName,* blktFileName, *resourcesFileName, *logFileName;

const int FAIL_LOGIN_CODE=401;
const int SUCC_LOGIN_CODE=200;

unordered_map<string,int> cntHTimes;
unordered_map<string,long> cntHBw;
unordered_map<int, int> winTimes;
vector< pair<int, int> >  Vwin;

map<string,pair<int, int>> badLogin;


void findTopHTimes() {
    priority_queue< hostValue, vector<hostValue>, compVal >   topHost;
    list<hostValue> revList;
    // Load our data
    int k=10;
    int i=1;
    hostValue uv;
//  Computing top 10 hosts by value using a priority queue
    for( auto it = cntHTimes.begin(); it!= cntHTimes.end(); it++ ){
         uv.ip = it->first;
         uv.val= it->second;
 //        cout<< uv.ip << " " << uv.val <<endl;
        if (i<=k ) {
            topHost.push(uv); i++;
        } else  if  (uv.val > (topHost.top()).val ) {
                 topHost.pop();
                 topHost.push(uv);
        }
    }
    while (!topHost.empty()) {
        uv = topHost.top();
        revList.push_front( uv);
        topHost.pop();
    }
    fstream  fhosts;
    fhosts.open(hostsFileName, std::fstream::out  );
    for (auto it = revList.begin(); it!= revList.end(); it++ )
            fhosts << it->ip<<","<< it->val <<endl;
    fhosts << '\n';
    revList.clear();
    fhosts.close();

}

void findTopHBandW() {
    priority_queue< hostValue, vector<hostValue>, compVal >   topHost;
    list<hostValue> revList;
    // Load our data
    int k=10;
    int i=1;
    hostValue uv;
//  Computing top 10 hosts by value using a priority queue
    for( auto it = cntHBw.begin(); it!= cntHBw.end(); it++ ){
         uv.ip = it->first;
         uv.val= it->second;
 //        cout<< uv.ip << " " << uv.val <<endl;
        if (i<=k ) {
            topHost.push(uv); i++;
        } else  if  (uv.val > (topHost.top()).val ) {
                 topHost.pop();
                 topHost.push(uv);
        }
    }
    while (!topHost.empty()) {
        uv = topHost.top();
        revList.push_front( uv);
        topHost.pop();
    }
    fstream  fresources;
    fresources.open(resourcesFileName, std::fstream::out  );
    for (auto it = revList.begin(); it!= revList.end(); it++ )
            fresources << it->ip<<endl;
    fresources << '\n';
    revList.clear();
    fresources.close();

}


void findTopWindows() {
    priority_queue< winValue, vector<winValue>, wincompVal >   topWindow;
    list<winValue> revList;
    // Load our data
    int k=10;
    int i=1;
    winValue uv;
//  Computing top 10 windows by value using a priority queue
    for( auto it = Vwin.begin(); it!= Vwin.end(); it++ ){
         uv.winTime = it->first;
         uv.val= it->second;
        cout<< uv.winTime << " " << uv.val <<endl;
        if (i<=k ) {
            topWindow.push(uv); i++;
        } else  if  (uv.val > (topWindow.top()).val ) {
                 topWindow.pop();
                 topWindow.push(uv);
        }
    }
    while (!topWindow.empty()) {
        uv = topWindow.top();
        revList.push_front( uv);
        topWindow.pop();
    }
    fstream  fwin;
    time_t t;
    char datetime[30];
    fwin.open(hoursFileName ,std::fstream::out  );
    for (auto it = revList.begin(); it!= revList.end(); it++ ) {
        
        t = it->winTime+3600;
        struct tm *tm = localtime(&t);
        strftime(datetime, sizeof(datetime), "%d/%b/%Y:%H:%M:%S %z", tm);
            fwin << datetime<<","<< it->val <<endl;
    }        
    fwin << '\n';
    revList.clear();
    fwin.close();

}



// if blocking is required, return 1
void  process_badlogin(string ip, int time ) {
   int iniTime, count;
   count=0;
   if(badLogin.find( ip  ) == badLogin.end()) {
     badLogin[ip] = make_pair(time, 1); 
   }
   else {
     iniTime = badLogin[ip].first;
     if (time-iniTime<=60) {
        count = badLogin[ip].second;
        count++;
        if (count >= 3) {
           badLogin[ip]= make_pair(time, count);  
          // cout<< "!!! WARNING IP:" <<ip<<'\n';
        } else
           badLogin[ip]= make_pair(badLogin[ip].first, count);  
     } 
     else { // reset counter to 1
        badLogin[ip]= make_pair(time,1 );  
 
     }
   }

}

int require_log( string ip, int time ) {
   pair<int, int> p; 
   if(badLogin.find( ip  ) != badLogin.end()) 
        p = badLogin[ip];
   else return 0;     
   if ( p.second >=3 ) {
        if (  time - p.first <= 300) {
            cout<< "@@@ LOG REQ \n";
            return 1 ;
        }
        else {
           badLogin.erase(ip); 
           return 0;           
        }
   }     
   else return 0;
}

void proc_log() {
    ifstream fin;
    fstream  fblk;
    fin.open(logFileName);
    fblk.open(blktFileName, std::fstream::out  );
    string line;
    char c,q1,q2;
    int  dd,yy, hh, mm, ss, reply, bb, z, nbytes;
    int  time, windowCnt, windowStartTime, init, curr;
    init=0;windowCnt=0; 
    list<int> window; 
    string  sip, s1, s2, stype, sres, sprot, sbytes, url;
    while( getline(fin, line ) ) {
        std::istringstream iss(line);
        if (!(iss >> sip >> c >>c >> c>> dd >>c >>c >>c >>c >>c >>yy >>c >>hh >>c >>mm >>c >>ss ))
            continue;  // error
        if (!(iss >>s2 >>q1))
           continue;
        time = ss+mm*60+hh*60*60 + (dd-1)*60*60*24 + 804571200;
        if (init==0 ) 
            windowStartTime=  time;
        init++;
        while ( q2 != '/' && iss>>q2 ) { } 
        iss>>q2;
        iss.putback(q2); 
        iss>>sres;
        q2=0;
        if (sres.back()!='"')
           while ( q2 != '"' && iss>>q2) { }
        while ( windowStartTime+3600< time ) {
            window.pop_front();
            windowStartTime= *(window.begin());
            windowCnt--;
        }  
        window.push_back(time);
        windowCnt++; 
        if (init==1 ) { 
            Vwin.push_back(make_pair(time,windowCnt) );
            curr=0;
        }     
  //      cout<< windowCnt<<' '<<time<<'\n';;
        q2=0; 
        // incrementing    counter for host      
        if(cntHTimes.find( sip ) == cntHTimes.end()) 
            cntHTimes[sip]=1;
        else 
            cntHTimes[sip]+=1;       
        if (time -3600 > Vwin[curr].first) {
            curr++;
            Vwin.push_back(make_pair(time,windowCnt)) ;          
        } else if (windowCnt>Vwin[curr].second) {
            Vwin[curr].second = windowCnt; 
            Vwin[curr].first= time; 
        }   
       
       if (!(iss >> reply>>sbytes)) { continue; } // error
        if (sbytes== "-" )nbytes=0; else nbytes= stoi(sbytes);
        if(cntHBw.find( sres  ) == cntHBw.end()) 
            cntHBw[sres]=nbytes;
        else 
            cntHBw[sres]+=nbytes;
        if (reply == 401) 
            process_badlogin( sip, time );
        if (reply== 401 || reply == 200 ) 
         // login for an specific IP is required if IP was blocked less than 300 sec ago
             if (require_log( sip, time ) )
                  fblk<<line<<'\n';
 //       cout<< "R:"<<reply<< " B: " << sbytes<<'\n';  
        sres= "";        
    }
    fblk.close();
}



int main(int argc, char** argv) {
    logFileName=argv[1];
    hostsFileName=argv[2];
    hoursFileName=argv[3];
    resourcesFileName=argv[4];
    blktFileName=argv[5];
    // Load our data
    proc_log();
    findTopHTimes();  
    findTopHBandW(); 
    findTopWindows();

    return 0;

}
