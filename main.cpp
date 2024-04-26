#include <iostream>
#include <cstdlib>
#include <pthread.h>
#include <semaphore.h>
#include <vector>
#include <cmath>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <chrono>

#define LISTEN_PORT 40000
#define SEND_PORT 40001
#define WAIT_TIME 2000
#define WAIT_TIME_DISTR 300
#define BUFF_SIZE sizeof(Message)
#define SERVER_EXIST_TIME 2

int Mask = 24;

class IpAddr
{
public:
    short mask;
    unsigned int addr;

    IpAddr(){}
    IpAddr(unsigned int addr, short mask)
    {
        this->addr = addr;
        this->mask = mask;
    }

    IpAddr NetAddr() const
    {
        int m = 32 - mask;

        return IpAddr((addr >> m) << m, mask);
    }

    IpAddr(const IpAddr& other)
    {
        addr = other.addr;
        mask = other.mask;
    }

    IpAddr(const std::string str, short mask)
    {
        std::string copy = str;
        addr = 0;
        this->mask = mask;
        for(int i = 0; i < 4; ++i)
        {
            int pos = copy.find_first_of('.');
            unsigned long oct = std::stoi(copy.substr(0, pos));
            // std::cout << "Oct " << i << " : " << oct << "\n";
            addr |= oct << (24 - i * 8);
            // std::cout << "In addr " << ((addr << i * 8) >> 24 ) << "\n";
            copy = copy.substr(pos + 1);
        }
    }

    // from 0 to 3
    unsigned int oct(int n) const
    {
        return ((addr << n * 8) >> 24);
    }

    std::string ToString() const
    {
        std::string res = "";
        for(int i = 0; i < 4; ++i)
        {
            res += std::to_string(oct(i));
            res += '.';
        }

        return res.substr(0, res.size() - 1) + "/" + std::to_string(mask);
    }

    std::string ToStringWithoutMask() const
    {
        std::string res = "";
        for(int i = 0; i < 4; ++i)
        {
            res += std::to_string(oct(i));
            res += '.';
        }

        return res.substr(0, res.size() - 1);
    }

    unsigned long host_number()
    {
        return (addr << mask) >> mask;
    }

    void set_host(unsigned long host)
    {
        int m = 32 - mask;

        addr = ((addr >> m) << m) | (host << m) >> m;
    }


};

std::string get_network_info() {
    FILE* pipe = popen("ip route show", "r");
    if (!pipe) return "Error";
    
    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    
    pclose(pipe);
    return result;
}

std::string execute_command(std::string command)
{
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) return "Error";
    
    char buffer[128];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 128, pipe) != NULL)
            result += buffer;
    }
    
    pclose(pipe);
    return result;
} 

struct TaskArg
{
    sem_t* sem;
    std::vector<IpAddr>* v;
    short mask;
    IpAddr addr;
};

void* task(void* taskArg)
{
    TaskArg ta = *(TaskArg*)taskArg;

    std::string res = execute_command("ping -w 6 -c 3 " + ta.addr.ToStringWithoutMask() + " > /dev/null && echo " + ta.addr.ToStringWithoutMask());

    if(res.length() != 0)
    {
        res = res.substr(0, res.length() - 1);
        IpAddr addr = IpAddr(res, ta.mask);
        sem_wait(ta.sem);
        ta.v->push_back(addr);
        sem_post(ta.sem);
    }

    delete taskArg;

    return NULL;
}

std::vector<IpAddr> pingall(IpAddr myAddr, short mask)
{
    sem_t* sem = new sem_t();
    if(sem_init(sem, 0, 1))
    {
        perror("Sem init error");
    }

    std::vector<IpAddr> v;
    pthread_t tids[254];
    for (int i = 1; i < 255; ++i)
    {
        TaskArg* ta = new TaskArg();
        ta->addr = IpAddr(myAddr);
        ta->addr.set_host(i);
        ta->sem = sem;
        ta->v = &v;
        ta->mask = mask;
        pthread_create(tids + i - 1, NULL, task, ta);
    }

    for (int i = 0; i < 254; ++i)
    {
        pthread_join(tids[i], NULL);
    }

    sem_close(sem);
    sem_destroy(sem);
    delete sem;

    return v;
}

// void configure_network(std::string ip_address, std::string netmask, std::string gateway) {
//     system(("ifconfig eth0 " + ip_address + " netmask " + netmask).c_str());
//     system(("route add default gw " + gateway).c_str());
// }

std::vector<std::string> new_addrs(const std::vector<std::string>& old)
{
    std::cout << "size " << old.size() << "\n";
    float bits = ceil(log(old.size() + 2)/ log(2));
    std::cout << "bits " << bits << "\n";
    bits = bits + 0.5;
    int int_bits = bits;
    int mask = 32 - int_bits;
    std::cout << "new mask " << mask << std::endl;
    
    std::string base = "192.168.1.";
    std::vector<std::string> newAddrs;

    for (int i = 0; i < old.size(); ++i)
    {
        newAddrs.push_back(base + std::to_string(i + 1));
        std::cout << "old: " << old[i] << ", new " << newAddrs[i] << "\n";
    }

    return newAddrs;
}

int host_number(std::string addr, std::string base)
{
	return std::stoi(addr.substr(base.size()));
}

void sort_addrs(std::vector<IpAddr>& addrs)
{
	for(int i = 0; i < addrs.size(); ++i)
	{
		for(int j = 0; j < addrs.size() - 1 - i; ++j)
		{
			if(addrs[j].addr > addrs[j+1].addr)
			{
				IpAddr tmp = addrs[j];
				addrs[j] = addrs[j+1];
				addrs[j+1] = tmp;
			}
		}
	}
}



sockaddr_in create_sockaddr(int port, std::string ip = "")
{
    sockaddr_in addr; 
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (ip == "")
    {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    else
    {
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
    }

    return addr;
}

int create_socket(int port)
{
    auto sock_addr = create_sockaddr(port);
    int descriptor;
    if((descriptor = socket(PF_INET, SOCK_DGRAM, 0)) < 0){
        std::cout << "Error in creating socket\n";
        perror(NULL); /* Печатаем сообщение об ошибке */
        exit(1);
    }

    if(bind(descriptor, (sockaddr *) &sock_addr, sizeof(sock_addr)) < 0){
        std::cout << "Error nigga\n";
        perror(NULL);
        close(descriptor);
        exit(1);
    }

    return descriptor;
}

struct DistrArgs
{
    sem_t* sem_flag;
    IpAddr myAddr;
    std::vector<IpAddr> addrs;
    bool* flag;
    sem_t* sem_console;
};

struct Message
{
    IpAddr sender;
};

void* DoDistr(void* void_arg)
{
    DistrArgs* args = (DistrArgs*)void_arg;

    int sender = create_socket(SEND_PORT);
    

    for (int i = 0; i < args->addrs.size(); ++i)
    {
        if(args->addrs[i].addr == args->myAddr.addr) continue;
        sockaddr_in receiver = create_sockaddr(LISTEN_PORT, args->addrs[i].ToStringWithoutMask());
        Message messg;
        messg.sender = args->myAddr;
        if(sendto(sender, &messg, BUFF_SIZE, 0,(struct sockaddr *) &receiver, sizeof(receiver)) < 0)
        {
            std::cout << "Error in send\n";

            perror(NULL);
            close(sender);
            exit(1);
        }
        sem_wait(args->sem_console);
        std::cout << "Sended to " << args->addrs[i].ToString() << "\n";
        sem_post(args->sem_console);
    }

    sem_wait(args->sem_flag);
    *(args->flag) = true;
    sem_post(args->sem_flag);
    close(sender);
    return NULL;
}

int createTcpSocket(int port)
{
    int descriptor;
    if((descriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)))
    {
        perror(NULL);
        exit(1);
    }

    sockaddr_in addr = create_sockaddr(port);
    if(bind(descriptor, (sockaddr*)&addr, sizeof(addr)) < 0)
    {
        perror(NULL);
        exit(1);
    }
    
    return descriptor;
}

struct TcpMessage
{
    IpAddr addr;
};

void tcpServer()
{
    int listener = createTcpSocket(LISTEN_PORT);

    int start = time(NULL);

    while(time(NULL) < start + SERVER_EXIST_TIME)
    {
        int fd;
        if(listen(listener, 10) != 0)
        {
            perror(NULL);
            exit(1);
        }

        fd = accept(listener, NULL, NULL);
        if(fd < 0)
        {
            perror(NULL);
        }

        TcpMessage messg;
        read(fd, &messg, sizeof(messg));

        // logic
        TcpMessage response;
        response.addr = IpAddr("192.168.1.3", 24);

        write(fd, &response, sizeof(response));
    }
    std::cout << "Exiting server";
    close(listener);
}

IpAddr ask_server(IpAddr myaddr)
{
    int sender = createTcpSocket(SEND_PORT);

    sockaddr_in serv = create_sockaddr(LISTEN_PORT);
    if(connect(sender, (sockaddr*)&serv, sizeof(serv)))
    {
        perror(NULL);
        exit(1);
    }

    TcpMessage messg;
    messg.addr = myaddr;
    write(sender, &messg, sizeof(messg));
    TcpMessage resp;
    
    read(sender, &resp, sizeof(resp));

    close(sender);
    return resp.addr;
}

IpAddr get_new_addr(IpAddr myaddr, std::vector<IpAddr> addrs)
{
    for (int i = 0; i < addrs.size(); ++i)
    {
        if(addrs[i].host_number() == 2)
        {
            return ask_server(myaddr);
        }
    }

    // start listen
    bool isFirst = true;
    int listener = create_socket(LISTEN_PORT);
    int wait_time = WAIT_TIME;
    timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = WAIT_TIME;
    setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    Message messg;

    sockaddr_in sender;
    socklen_t sender_len;
    int n = 0;

    int start = std::chrono::duration_cast<std::chrono::milliseconds >(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    int now = std::chrono::duration_cast<std::chrono::milliseconds >(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    while (now < start + WAIT_TIME)
    {
        // std::cout << "Current time " << time(NULL) << "\n";
        bool recvFlag;
        if (n = recvfrom(listener, &messg, BUFF_SIZE, 0, (sockaddr*)&sender, &sender_len) < 0)
        {
            if(errno != EAGAIN && errno != EWOULDBLOCK)
            {
                std::cout << "Error in recvfrom in listen stage\n";
                perror(NULL);
                exit(1);
            }

            recvFlag = false;
        }
        if(recvFlag)
        {
            std::cout << "Received from in wait state " << messg.sender.ToString() << "\n";
            isFirst = false;

        }

        now = std::chrono::duration_cast<std::chrono::milliseconds >(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
    }

    if(!isFirst)
    {
        sleep(2);
        return ask_server(myaddr);
    }



    std::vector<IpAddr> collisions;
    sem_t* sem_flag = new sem_t();
    if(sem_init(sem_flag, 0, 1))
    {
        perror("Sem init error");
        exit(1);
    }

    sem_t* sem_console = new sem_t();
    if(sem_init(sem_console, 0, 1))
    {
        perror("Sem init error");
        sem_close(sem_flag);
        sem_destroy(sem_flag);
        exit(1);
    }

    bool isDoneDistr = false;

    DistrArgs* args = new DistrArgs();
    args->sem_flag = sem_flag;
    args->flag = &isDoneDistr;
    args->myAddr = myaddr;
    args->addrs = addrs;
    args->sem_console = sem_console;
    pthread_t pid;
    pid = pthread_create(&pid, NULL, DoDistr, args);

    std::cout << "Start sending messages\n";

    tv.tv_sec = 0;
    tv.tv_usec = WAIT_TIME_DISTR;
    setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    while(true)
    {
        sem_wait(sem_flag);
        if(isDoneDistr)
        {
            sem_post(sem_flag);
            break;
        }
        sem_post(sem_flag);
        bool recvFlag = true;
        if (n = recvfrom(listener, &messg, BUFF_SIZE, 0, (sockaddr*)&sender, &sender_len) < 0)
        {
            // sem_wait(sem_console);
            // std::cout << "Not received\n";
            // sem_post(sem_console);

            if(errno != EAGAIN && errno != EWOULDBLOCK)
            {
                std::cout << "Error in recvfrom in listen stage\n";
                perror(NULL);

                sem_close(sem_flag);
                sem_destroy(sem_flag);

                sem_close(sem_console);
                sem_destroy(sem_console);
                delete sem_flag;
                delete sem_console;

                exit(1);
            }
            
            recvFlag = false;
        }

        if (recvFlag)
        {
            sem_wait(sem_console);
            std::cout << "Received from in wait thread " << messg.sender.ToString() << "\n";
            sem_post(sem_console);
            collisions.push_back(messg.sender);
        }
    }
    sem_close(sem_flag);
    sem_destroy(sem_flag);

    sem_close(sem_console);
    sem_destroy(sem_console);
    delete sem_flag;
    delete sem_console;

    close(listener);

    bool amIServer = true;
    if(!collisions.empty())
    {
        for(int i = 0; i < collisions.size(); ++i)
        {
            if(collisions[i].host_number() < myaddr.host_number())
            {
                amIServer = false;
            }
        }
    }
    
    if(amIServer)
    {
        // fork()
        
        int pid = fork();
        if(pid < 0)
        {
            perror(NULL);
            exit(1);
        }
        if(pid == 0)
        {
            tcpServer();
            exit(0);
        }

        std::cout << "CHild process start\n";

        IpAddr res = myaddr;
                
        res.set_host(0);
        float bits = ceil(log(addrs.size() + 2)/ log(2));
        bits = bits + 0.5;
        int int_bits = bits;
        int mask = 32 - int_bits;
        res.mask = mask;
        res.set_host(2);

        return res;
    }

    // wait til .2 shows up
    float bits = ceil(log(addrs.size() + 2)/ log(2));
    bits = bits + 0.5;
    int int_bits = bits;
    Mask = 32 - int_bits;
    return ask_server(myaddr);
}

IpAddr findMyAddr()
{
    std::string res = execute_command("ip -o -f inet addr show | awk '/scope global/ {print $4}'");
    
    int pos = res.find_first_of('/');
    short mask = std::stoi(res.substr(pos + 1));
    res = res.substr(0, pos);
    return IpAddr(res, mask);
}

int main() {
	// Анализ информации о сети и автоматическая настройка параметров
    // Здесь можно добавить логику для анализа и определения параметров ip_address, netmask, gateway
    IpAddr myAddr = findMyAddr();
    std::cout << "My addr " + myAddr.ToString() << "\n";
    std::vector<IpAddr> addrs = pingall(myAddr, myAddr.mask);
    sort_addrs(addrs);
    for(IpAddr addr : addrs)
    {
        std::cout << addr.ToString() << "\n";
    }

    IpAddr res = get_new_addr(myAddr, addrs);
    std::cout << "MyNew addr " <<  res.ToString() << "\n";

    // auto newAddrs = new_addrs(addrs);
	
    // Пример автоматической настройки сетевых параметров
    // configure_network("192.168.1.100", "255.255.255.0", "192.168.1.1");
    
    return 0;
}

/* 
ладно ребята давайте в последний раз
на адресном сервере создается список с мапами адресов (или используется созданный!!!)

в) на втором адресе запускается сервак, который составляет преобразование адресов
при наличии второго адреса на него посылается запрос с вопросом бро какой у меня айпишник
и этот айпишник применяется
как понять что мы на втором адресе?
наш адрес минимальный
`
2 случая: все одновременно и в разные моменты времени
если все одновременно, то делается некоторая пауза в течение которой по-любому запустится сервак
если в разные моменты времени, то нужно понять запущен ли уже сервер. 
подразумевается что вторым адресом всегда будет комп на котором будет запущен сервак.
Если второго адреса нет то его должен занять первый чел как понять что чел первый?

так
адрес должен получить первый запустивший с минимальным адресом
для этого челики делают открывают тсп соединение и начинают общаться
выясняется кто самый минимальный и идет настройка адресного сервера
поэтому перед тем как начать общение мужики должны подождать и перепроверить. Мб без них уже добазарились
А пока ждут как раз могут все пропинговать.
то есть


а можем просто стать в режим прослушки если нам никто ничего не кинет то мы второй и начинаем рассылку
если кинет то ждем пока появится второй адрес
если при рассылке мы получаем пакет то запоминаем этот смельчака и потом сверяем наиманьший адрес

ну в общем так

в таком случае коллизии минимальны


потом все по тсп начинают получать адреса со второго адреса и всем хорошо
 */
/*
плэн
fork процесс для сервака
ожидание появления второго адреса
фотоматериалы
дан
*/