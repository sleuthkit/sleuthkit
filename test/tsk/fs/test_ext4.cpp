/* WORK IN PROGRESS - Do not run yet.
 * See https://github.com/sleuthkit/sleuthkit/issues/3132#issuecomment-2543858254
 */


#include <filesystem>
#include <vector>
#include <string>
#include <memory>
#include <iostream>
#include <tsk/libtsk.h>

int main()
{
    const std::filesystem::path file_path = std::filesystem::absolute("/bin/bash").lexically_normal();

    TskImgInfo img_info;
    uint8_t ret = img_info.open("/dev/sda1",  // !!!REPLACE WITH RELEVANT DEVICE!!!
                                TSK_IMG_TYPE::TSK_IMG_TYPE_DETECT,
                                0);

    if (ret != TSK_SUCCESS) {
        throw std::runtime_error("image open error");
    }

    TskFsInfo tsk_fs_info;
    const TSK_OFF_T NO_OFFSET = 0;
    ret = tsk_fs_info.open(&img_info, NO_OFFSET, TSK_FS_TYPE::TSK_IMG_TYPE_DETECT);

    if (ret != TSK_SUCCESS) {
        throw std::runtime_error("fs info open error");
    }

    const std::u8string relative_path = std::u8string("/") + file_path.relative_path().generic_u8string();

    TskFsFile tsk_file;
    ret = tsk_file.open(tsk_fs_info, &tsk_file, reinterpret_cast<const char*>(relative_path.c_str()));

    if (ret != TSK_SUCCESS) {
        throw std::runtime_error("open file error");
    }

    const size_t size_to_read = 66000; // More than 2^16
    TSK_OFF_T offset = 1;
    std::vector<uint8_t> out_buffer(size_to_read);
    const ssize_t bytes_read = tsk_file.read(offset,
                                             reinterpret_cast<char*>(out_buffer.data()),
                                             size_to_read,
                                             TSK_FS_FILE_READ_FLAG_ENUM::TSK_FS_FILE_READ_FLAG_NONE);

    std::cout << "size: " << bytes_read << std::endl;
    std::cout << std::ranges::all_of(out_buffer, [](uint8_t byte) { return bytes == 0; }) << std::endl;

    return 0;
}
