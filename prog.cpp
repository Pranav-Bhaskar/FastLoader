#include<iostream>
#include<arpa/inet.h>
#include<unistd.h>
#include<netdb.h>
#include<vector>
#include<cstring>
#include<string>
#include<openssl/ssl.h>
#include<openssl/err.h>

using namespace std;

vector<string> cutter(string str, char delimer){
	vector<string> cut;
	string temp;
	temp.clear();
	for(int i=0;i<str.length();++i){
		if(str[i] == delimer){
			if(!temp.empty())
				cut.push_back(temp);
			temp.clear();
			continue;
		}
		temp.push_back(str[i]);
	}
	if(!temp.empty())
		cut.push_back(temp);
	return cut;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);							/* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);							/* free the malloc'ed string */
        X509_free(cert);					/* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
}

class Link{
	string url;
	char* path;
	char* hostname;
	char* host;
	vector<string> part;
	void url2hostname();
	string request;
	struct hostent *he;
	public:
	unsigned long IP;
	int PORT;
	Link(char*);
	char* req();
};

Link::Link(char* u){
	this->url = u;
	hostname = new char[100];
	host = new char [100];
	strcpy(hostname, "");
	this->part = cutter(this->url, '/');
	this->url2hostname();
	this->path = new char[2000];
	strcpy(this->path, "/");
	for(int i=1;i<part.size();++i){
		strcat(this->path, part[i].c_str());
		strcat(this->path, "/");
	}
	if(strlen(this->path) > 1)
		this->path[strlen(this->path) - 1] = '\0';
	
	if((he = gethostbyname(hostname)) == NULL){
		cout<<"\ncouldnot resolve the hostname\n";
		exit(1);
	}
	IP = *(long*)(he->h_addr);
}

char* Link::req(){
	request = ("GET " + string(this->path) + " HTTP/1.1\r\nHost: " + this->host + "\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nDNT: 1\r\nUpgrade-Insecure-Requests: 1\r\n\r\n");
	char *req;
	req = new char[2000];
	strcpy(req, request.c_str());
	return req;
}

void Link::url2hostname(){
	if("https:" == part[0]){
		PORT = 443;
		part.erase(part.begin());
	}
	else if("http:" == part[0]){
		PORT = 80;
		part.erase(part.begin());
	}
	else if("ftp:" == part[0]){
		PORT = 21;
		part.erase(part.begin());
	}
	else
		PORT = 80;
	strcpy(this->host, this->part[0].c_str());
	vector<string> temp = cutter(this->part[0], '.');
	vector<string> tem = cutter(temp[temp.size() - 1], ':');
	if(tem.size() == 2){
		PORT = stoi(tem[1]);
		temp[temp.size() - 1] = tem[0];
	}
	if(temp.size() > 1){
		strcpy(hostname, temp[temp.size() - 2].c_str());
		strcat(hostname, ".");
	}
	strcat(hostname, temp[temp.size() - 1].c_str());
}

class FastLoad{
	Link* l;
	int sock;
	int con;
	char *request;
	int r_size;
	struct sockaddr_in sin;
	void conn();
	void conn_ssl();
	char buffer[1024];
	SSL_CTX* InitCTX();
	public:
	FastLoad(char*);
};

FastLoad::FastLoad(char* c){
	this->l = new Link(c);
	sock = socket(PF_INET, SOCK_STREAM, 0);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(l->PORT);
	sin.sin_addr.s_addr = l->IP;
	this->request = l->req();
	cout<<"\n\n<-----------REQUEST----------->\n"<<this->request;
	this->r_size = strlen(this->request);
	con = connect(sock, (struct sockaddr *)&sin, sizeof(sin));
	if(con < 0){
		cout<<"\nERROR : Couldnot establish a connection";
		cout<<con;
	}
	if(l->PORT == 443)
		this->conn_ssl();
	else
		this->conn();
}

SSL_CTX* FastLoad::InitCTX(){
	const SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	method = SSLv23_client_method();
	ctx = SSL_CTX_new(method);
	if(ctx == NULL){
		cout<<"\nError 1.";
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void FastLoad::conn_ssl(){
	SSL_CTX *ctx;
	SSL *ssl;
	int bytes = -69;
	ctx = InitCTX();
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, this->sock);
	int t;
	if((t = SSL_connect(ssl)) != 1){
		ERR_print_errors_fp(stderr);
		cout<<"Error : "<<t;
	}
	else{
		printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
		SSL_write(ssl, this->request, this->r_size);
		cout<<"\nReceived: \n\n";
		do{
			bytes = SSL_read(ssl, buffer, sizeof(buffer));
			buffer[bytes] = '\0';
			cout<<buffer;
			cout<<"\nbytes:"<<bytes<<endl;
		}while(bytes);
		SSL_free(ssl);
	}
	close(this->sock);
	SSL_CTX_free(ctx);
}

void FastLoad::conn(){
	send(sock, this->request, this->r_size, 0);
	read(sock, buffer, sizeof(buffer));
	cout<<"\n\n<-----------RESPONSE----------->\n"<<buffer;
}

int main(int argc, char const* argv[]){
	char* c;
	c = new char[600];
	cout<<"\nEnter Download link : ";
	cin>>c;
	FastLoad f(c);
	return 0;
}
