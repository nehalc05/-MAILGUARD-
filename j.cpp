#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <regex>
#include <set>
#include <algorithm>

using namespace std;

class Email
{
private:
    string sender;
    string subject;
    string body;
    vector<string> urls;

public:
    // Default Constructor
    Email()
    {
        sender = "";
        subject = "";
        body = "";
    }

    // Setter Functions
    void setSender(string s)
    {
        sender = s;
    }

    void setSubject(string s)
    {
        subject = s;
    }

    void appendBody(string line)
    {
        body += line + "\n";
    }

    void addURL(string url)
    {
        urls.push_back(url);
    }

    // Getter Functions
    string getSender() const
    {
        return sender;
    }

    string getSubject() const
    {
        return subject;
    }

    string getBody() const
    {
        return body;
    }

    vector<string>& getURLs()
    {
        return urls;
    }
};

class Report
{
private:
    int score;

public:

    // Sender Analysis
    bool businessEmail;
    bool freeProvider;
    bool brandImpersonation;

    // URL Analysis
    bool hasHTTP;
    bool hasHTTPS;
    bool hasIP;
    bool shortURL;
    bool suspiciousTLD;

    // Content Analysis
    bool urgency;
    bool prize;
    bool credential;
    bool promotion;

    vector<string> reasons;

    // Constructor
    Report()
    {
        score = 100;

        businessEmail = false;
        freeProvider = false;
        brandImpersonation = false;

        hasHTTP = false;
        hasHTTPS = false;
        hasIP = false;
        shortURL = false;
        suspiciousTLD = false;

        urgency = false;
        prize = false;
        credential = false;
        promotion = false;
    }

    void deductScore(int marks)
    {
        score -= marks;

        if(score < 0)
            score = 0;
    }

    int getScore() const
    {
        return score;
    }

    void addReason(string reason)
    {
        reasons.push_back(reason);
    }
};
string toLower(string s)
{
    transform(s.begin(), s.end(), s.begin(), ::tolower);
    return s;
}

bool contains(string text, string key)
{
    text = toLower(text);
    key = toLower(key);

    return text.find(key) != string::npos;
}

Email readEmail(const string &filename)
{
    Email mail;

    ifstream file(filename);

    if(!file)
    {
        cout << "Error: Unable to open " << filename << endl;
        return mail;
    }

    string line;

    while(getline(file, line))
    {
        if(line.empty())
            continue;

        if(line.rfind("From:", 0) == 0)
        {
            mail.sender = line.substr(6);
        }
        else if(line.rfind("Subject:", 0) == 0)
        {
            mail.subject = line.substr(9);
        }
        else
        {
            mail.body += line + "\n";
        }
    }

    file.close();

    return mail;
}
void extractURLs(Email &mail)
{
    regex url("(https?://[^\\s\"'>]+)");
    regex href("<a[^>]*href=[\"']([^\"']+)[\"']");

    set<string> uniqueURLs;

    auto begin = sregex_iterator(mail.body.begin(), mail.body.end(), url);
    auto end = sregex_iterator();

    for(auto i = begin; i != end; i++)
        uniqueURLs.insert((*i).str());

    auto hbegin = sregex_iterator(mail.body.begin(), mail.body.end(), href);

    for(auto i = hbegin; i != end; i++)
        uniqueURLs.insert((*i)[1].str());

    mail.urls.assign(uniqueURLs.begin(), uniqueURLs.end());
}

vector<string> loadData(const string &filename)
{
    vector<string> data;
    ifstream file(filename);

    string line;

    while(getline(file, line))
    {
        if(!line.empty())
            data.push_back(line);
    }

    file.close();
    return data;
}
string getDomain(const string &sender)
{
    size_t pos = sender.find('@');

    if(pos != string::npos)
        return sender.substr(pos + 1);

    return "";
}
void analyzeSender(Email &mail, Report &rep)
{
    string sender = toLower(mail.sender);
    string domain = getDomain(sender);

    vector<string> businessDomains = loadData("business_domains.txt");
    vector<string> freeProviders = loadData("free_email.txt");
    vector<string> brands = loadData("brand_names.txt");

    for(string business : businessDomains)
    {
        if(domain == business)
        {
            rep.businessEmail = true;
            break;
        }
    }

    for(string provider : freeProviders)
    {
        if(domain == provider)
        {
            rep.freeProvider = true;
            break;
        }
    }

    for(string brand : brands)
    {
        if(sender.find(brand) != string::npos && !rep.businessEmail)
        {
            rep.brandImpersonation = true;
            rep.score -= 25;
            rep.reasons.push_back("Possible brand impersonation.");
            break;
        }
    }
}
void analyzeURLs(Email &mail,Report &rep)
{
    regex ip("(\\d+\\.\\d+\\.\\d+\\.\\d+)");

    vector<string> shorteners={
        "bit.ly",
        "tinyurl",
        "t.co",
        "goo.gl",
        "is.gd"
    };

    vector<string> badTLD={
        ".xyz",
        ".top",
        ".click",
        ".live",
        ".site",
        ".online"
    };

    for(string url:mail.urls)
    {
        string u=toLower(url);

        if(u.find("http://")==0)
        {
            rep.hasHTTP=true;
            rep.score-=5;
            rep.reasons.push_back("Uses HTTP instead of HTTPS.");
        }

        if(u.find("https://")==0)
            rep.hasHTTPS=true;

        if(regex_search(u,ip))
        {
            rep.hasIP=true;
            rep.score-=25;
            rep.reasons.push_back("Contains IP address URL.");
        }

        for(string s:shorteners)
        {
            if(u.find(s)!=string::npos)
            {
                rep.shortURL=true;
                rep.score-=10;
                rep.reasons.push_back("Uses shortened URL.");
            }
        }

        for(string t:badTLD)
        {
            if(u.find(t)!=string::npos)
            {
                rep.suspiciousTLD=true;
                rep.score-=10;
                rep.reasons.push_back("Suspicious top-level domain.");
            }
        }
    }

    if(mail.urls.size()>3)
    {
        rep.score-=10;
        rep.reasons.push_back("Too many links in email.");
    }
}

vector<string> loadKeywords(const string &filename)
{
    vector<string> keywords;
    ifstream file(filename);

    string word;

    while(getline(file, word))
    {
        if(!word.empty())
            keywords.push_back(word);
    }

    file.close();
    return keywords;
}

void analyzeContent(Email &mail, Report &rep)
{
    string text = toLower(mail.subject + " " + mail.body);

    vector<string> urgency = loadKeywords("urgency.txt");
    vector<string> prize = loadKeywords("prize.txt");
    vector<string> credential = loadKeywords("credential.txt");
    vector<string> promotion = loadKeywords("promotion.txt");

    for(string k : urgency)
    {
        if(contains(text, k))
        {
            rep.urgency = true;
            rep.score -= 8;
            rep.reasons.push_back("Urgency language detected.");
            break;
        }
    }

    for(string k : prize)
    {
        if(contains(text, k))
        {
            rep.prize = true;
            rep.score -= 12;
            rep.reasons.push_back("Prize or reward language detected.");
            break;
        }
    }

    for(string k : credential)
    {
        if(contains(text, k))
        {
            rep.credential = true;
            rep.score -= 15;
            rep.reasons.push_back("Credential request detected.");
            break;
        }
    }

    for(string k : promotion)
    {
        if(contains(text, k))
        {
            rep.promotion = true;
            break;
        }
    }
}string getRiskLevel(int score)
{
    if(score >= 90)
        return "VERY SAFE";

    if(score >= 70)
        return "PROBABLY SAFE";

    if(score >= 50)
        return "SUSPICIOUS";

    if(score >= 30)
        return "HIGH RISK";

    return "LIKELY PHISHING";
}

void printReport(Email &mail, Report &rep)
{
    cout << "\n=====================================\n";
    cout << "        MAILGUARD REPORT\n";
    cout << "=====================================\n\n";

    cout << "Sender : " << mail.sender << endl;
    cout << "Subject: " << mail.subject << endl;

    cout << "\n----------- Sender Analysis -----------\n";

    if(rep.businessEmail)
        cout << "Business Domain          : YES\n";
    else
        cout << "Business Domain          : NO\n";

    if(rep.freeProvider)
        cout << "Free Email Provider      : YES\n";
    else
        cout << "Free Email Provider      : NO\n";

    if(rep.brandImpersonation)
        cout << "Brand Impersonation      : YES\n";
    else
        cout << "Brand Impersonation      : NO\n";


    cout << "\n----------- URL Analysis -----------\n";

    cout << "URLs Found : " << mail.urls.size() << endl;

    for(string url : mail.urls)
        cout << "   " << url << endl;

    cout << "\nHTTP Used               : "
         << (rep.hasHTTP ? "YES" : "NO") << endl;

    cout << "HTTPS Used              : "
         << (rep.hasHTTPS ? "YES" : "NO") << endl;

    cout << "IP Address URL          : "
         << (rep.hasIP ? "YES" : "NO") << endl;

    cout << "Shortened URL           : "
         << (rep.shortURL ? "YES" : "NO") << endl;

    cout << "Suspicious TLD          : "
         << (rep.suspiciousTLD ? "YES" : "NO") << endl;


    cout << "\n----------- Content Analysis -----------\n";

    cout << "Urgency                 : "
         << (rep.urgency ? "YES" : "NO") << endl;

    cout << "Prize / Reward          : "
         << (rep.prize ? "YES" : "NO") << endl;

    cout << "Credential Request      : "
         << (rep.credential ? "YES" : "NO") << endl;

    cout << "Promotion               : "
         << (rep.promotion ? "YES" : "NO") << endl;


    if(rep.score < 0)
        rep.score = 0;

    cout << "\n=====================================\n";
    cout << "Trust Score : " << rep.score << "/100\n";
    cout << "Risk Level  : " << getRiskLevel(rep.score) << endl;

    cout << "\nReasons:\n";

    if(rep.reasons.empty())
    {
        cout << "No suspicious indicators detected.\n";
    }
    else
    {
        for(string reason : rep.reasons)
            cout << "- " << reason << endl;
    }

    cout << "\nRecommendation:\n";

    if(rep.score >= 90)
    {
        cout << "Looks safe.\n";
    }
    else if(rep.score >= 70)
    {
        cout << "Probably safe, but verify before clicking links.\n";
    }
    else if(rep.score >= 50)
    {
        cout << "Exercise caution before interacting.\n";
    }
    else
    {
        cout << "Do NOT click links or download attachments.\n";
        cout << "Verify the sender through an official website.\n";
    }

    cout << "\n=====================================\n";
}

int main()
{
   Email mail;
    Report report;

    cout << "Paste the complete email below.\n";
    cout << "Type END on a new line when finished.\n\n";

    string line;

    while(getline(cin,line))
    {
        if(line=="END")
            break;

        if(line.rfind("From:",0)==0)
            mail.sender=line.substr(5);

        else if(line.rfind("Subject:",0)==0)
            mail.subject=line.substr(8);

        else
            mail.body+=line+"\n";
    }

    extractURLs(mail);

    analyzeSender(mail,report);
    analyzeURLs(mail,report);
    analyzeContent(mail,report);

    printReport(mail,report);

    return 0;
}