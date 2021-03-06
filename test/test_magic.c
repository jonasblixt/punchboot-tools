#include "nala.h"
#include <pb-tools/wire.h>

TEST(magic)
{
    struct pb_command cmd;
    struct pb_result result;
    int rc;

    rc = pb_wire_init_command(&cmd, PB_CMD_INVALID);

    ASSERT_EQ(rc, PB_RESULT_OK);
    ASSERT_EQ(cmd.magic, PB_WIRE_MAGIC);
    ASSERT_EQ(cmd.magic, 0x50424c30   /* PBL0 */);

    rc = pb_wire_init_result(&result, PB_RESULT_OK);

    ASSERT_EQ(rc, PB_RESULT_OK);
    ASSERT_EQ(result.magic, PB_WIRE_MAGIC);
    ASSERT_EQ(result.magic, 0x50424c30   /* PBL0 */);
}

TEST(invalid_command)
{
    struct pb_command cmd;
    int rc;

    rc = pb_wire_init_command(&cmd, PB_CMD_INVALID);
    ASSERT_EQ(rc, PB_RESULT_OK);

    ASSERT(!pb_wire_valid_command(&cmd));
}

TEST(valid_command)
{
    struct pb_command cmd;
    int rc;

    rc = pb_wire_init_command(&cmd, PB_CMD_DEVICE_RESET);
    ASSERT_EQ(rc, PB_RESULT_OK);

    ASSERT(pb_wire_valid_command(&cmd));
}
