#ifndef _DATA_SOURCE_H_
#define _DATA_SOURCE_H_

#include <string>
#include <memory>
#include <vector>

namespace Erpiko {

/**
 * DataSource class
 */
class DataSource {
  public:
    virtual ~DataSource();

    /**
     * Create a new DataSource from vector
     * @param data Vector containing data
     * @return a new DataSource
     */
    static DataSource* fromVector(const std::vector<unsigned char> data);

    /**
     * Create a new DataSource from file
     * @param path to the file
     * @return a new DataSource
     */
    static DataSource* fromFile(const std::string fileName);

    /**
     * Reads all data and put it in a vector
     * @return reference to the vector containing data
     */
    const std::vector<unsigned char>& readAll();

  private:
    class Impl;
    std::unique_ptr<Impl> impl;
    DataSource();
};

} // namespace Erpiko

#endif // _DATA_SOURCE_H_
