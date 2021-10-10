#ifndef VERSIONCHECKER_H
#define VERSIONCHECKER_H

#include <QObject>
// #include <iostream>

#define KOMODO_RELEASES "https://api.github.com/repos/DeckerSU/KomodoOcean/tags"
#define KOMODO_LATEST_RELEASE "https://github.com/DeckerSU/KomodoOcean/releases/latest"


class Version {

public:
    int _major;
    int _minor;
    int _revision;

    Version(){
        SetNull();
    }

    Version(int maj, int min, int rev){
        SetNull();

        _major = maj;
        _minor = min;
        _revision = rev;
    }

    Version(QString str){
        SetNull();

        QStringList parts = str.split(".");

        for (int i = 0; i < parts.length(); i++) {
            if (i == 0 && parts[i].left(1) == "v")
                parts[i] = parts[i].right(parts[i].size() - 1);
            if (i == 2 && parts[i].contains("-"))
                parts[i] = parts[i].left(parts[i].indexOf("-"));
            // std::cerr << i << ". " << parts[i].toStdString() << std::endl;
        }

        if(!parts.isEmpty())
            _major = parts[0].toInt();
        if(parts.length() > 1)
            _minor = parts[1].toInt();
        if(parts.length() > 2)
            _revision = parts[2].toInt();
    }

    Version(const Version &v){
        _major = v._major;
        _minor = v._minor;
        _revision = v._revision;
    }

    bool operator >(const Version& other) const
    {
        return compareAll(other) > 0;
    }

    bool operator <(const Version& other) const
    {
        return compareAll(other) < 0;
    }

    bool operator ==(const Version& other) const
    {
        return compareAll(other) == 0;
    }

    void SetNull()
    {
        _major = 0;
        _minor = 0;
        _revision = 0;
    }

    std::string ToString() const;

private:
    int compare(int first, int second) const
    {
        int diff = first - second;
        return diff > 0 ? 1 : diff < 0 ? -1 : 0;
    }
    int compareAll(const Version& other) const
    {
        return 1000000 * compare(_major, other._major) +
               10000 * compare(_minor, other._minor) +
               100 * compare(_revision, other._revision);
    }
};

class KomodoVersionChecker : public QObject
{
    Q_OBJECT
public:
    explicit KomodoVersionChecker(QObject *parent = 0);
    ~KomodoVersionChecker();

    bool newVersionAvailable();

private:
    QList<Version> getVersions();
    Version getMaxReleaseVersion();

    Version currentVersion;
};

#endif // VERSIONCHECKER_H
