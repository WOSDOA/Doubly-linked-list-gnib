#ifndef BITCOINUNITS_H
#define BITCOINUNITS_H

#include <QString>
#include <QAbstractListModel>

/** MaxCoin unit definitions. Encapsulates parsing and formatting
   and serves as list model for drop-down selection boxes.
*/
class BitcoinUnits: public QAbstractListModel
{
    Q_OBJECT

public:
    explicit BitcoinUnits(QObject *parent);

    /** MaxCoin units.
      @note Source: https://en.bitcoin.it/wiki/Units . Please add only sensible ones
     */
    enum Unit
    {
        MAX,
        mMAX,
        uMAX
    };

    //! @name Static API
    //! Unit conversion and formatting
    ///@{

    //! Get list of units, for drop-down box
    static QList<Unit> availableUnits();
    //! Is unit ID valid?
    static bool valid(int unit);
    //! Short name
    static QSt