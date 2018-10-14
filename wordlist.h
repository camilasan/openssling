#ifndef WORDLIST_H
#define WORDLIST_H

#include <QList>
#include <QString>

namespace WordList {
    QStringList getRandomWords(int nr);
    QString getUnifiedString(const QStringList& l);
}

#endif // WORDLIST_H
