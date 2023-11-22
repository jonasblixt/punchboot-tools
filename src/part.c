#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <bpak/bpak.h>
#include <bpak/utils.h>
#include <bpak/id.h>
#include <inttypes.h>
#include "tool.h"
#include "uuid/uuid.h"
#include "sha256.h"

#define PART_VERIFY_CHUNK_SZ (1024*1024)

static int part_verify(struct pb_context *ctx, const char *filename, const char *part_uuid)
{
    struct bpak_header header;
    bool bpak_file = false;
    uuid_t uu_part;
    uint8_t hash_data[32];
    int rc;
    FILE *fp = fopen(filename, "rb");
    mbedtls_sha256_context sha256;
    size_t file_size = 0;

    mbedtls_sha256_init(&sha256);
    mbedtls_sha256_starts_ret(&sha256, 0);

    if (!fp)
    {
        fprintf(stderr, "Error: Could not open '%s'\n", filename);
        return -PB_RESULT_ERROR;
    }

    if (uuid_parse(part_uuid, uu_part) != 0) {
        fprintf(stderr, "Error: Invalid UUID\n");
        return -PB_RESULT_INVALID_ARGUMENT;
    }

    size_t read_bytes = fread(&header, 1, sizeof(header), fp);

    if (read_bytes == sizeof(header) &&
        (bpak_valid_header(&header) == BPAK_OK))
    {
        if (pb_get_verbosity() > 0)
        {
            printf("Detected bpak header\n");
        }

        bpak_file = true;

        rc = mbedtls_sha256_update_ret(&sha256, (unsigned char *) &header,
                                                sizeof(header));

        if (rc != 0)
        {
            rc = -PB_RESULT_ERROR;
            goto err_out;
        }

        file_size += sizeof(header);
    }
    else
    {
        fseek(fp, 0, SEEK_SET);
    }

    unsigned char *chunk_buffer = malloc(PART_VERIFY_CHUNK_SZ);

    if (!chunk_buffer)
    {
        rc = -PB_RESULT_NO_MEMORY;
        goto err_out;
    }

    while ((read_bytes = fread(chunk_buffer, 1, PART_VERIFY_CHUNK_SZ, fp)) > 0)
    {
        rc = mbedtls_sha256_update_ret(&sha256, chunk_buffer, read_bytes);

        if (rc != 0)
        {
            rc = -PB_RESULT_ERROR;
            goto err_free_out;
        }

        file_size += read_bytes;
    }

    mbedtls_sha256_finish_ret(&sha256, hash_data);

    rc = pb_api_partition_verify(ctx, uu_part, hash_data, file_size, bpak_file);

err_free_out:
    free(chunk_buffer);
err_out:
    fclose(fp);
    return rc;
}

static int part_write(struct pb_context *ctx, const char *filename, const char *part_uuid)
{
    int rc;
    int fd;
    uuid_t uu_part;

    if (uuid_parse(part_uuid, uu_part) != 0) {
        fprintf(stderr, "Error: Invalid UUID\n");
        return -PB_RESULT_INVALID_ARGUMENT;
    }

    fd = open(filename, O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "Error: Could not open '%s'\n", filename);
        return -PB_RESULT_NOT_FOUND;
    }

    if (pb_get_verbosity() > 0) {
        printf("Writing '%s' to '%s'\n", filename, part_uuid);
    }

    rc = pb_api_partition_write(ctx, fd, uu_part);

    close(fd);
    return rc;
}

static int part_list(struct pb_context *ctx)
{
    struct pb_partition_table_entry *tbl;
    char uuid_str[37];
    int entries = 128;
    int rc = -PB_RESULT_ERROR;

    tbl = malloc(sizeof(struct pb_partition_table_entry) * entries);

    rc = pb_api_partition_read_table(ctx, tbl, &entries);

    if (rc != PB_RESULT_OK)
        goto err_out;

    if (!entries)
        goto err_out;

    printf("%-37s   %-8s   %-7s   %-16s\n",
                "Partition UUID",
                "Flags",
                "Size",
                "Name");
    printf("%-37s   %-8s   %-7s   %-16s\n",
                "--------------",
                "-----",
                "----",
                "----");

    for (int i = 0; i < entries; i++)
    {
        size_t part_size = (tbl[i].last_block - tbl[i].first_block + 1) * \
                            tbl[i].block_size;
        char size_str[16];
        char flags_str[9] = "--------";

        uuid_unparse(tbl[i].uuid, uuid_str);
        bytes_to_string(part_size, size_str, sizeof(size_str));
        uint8_t flags = tbl[i].flags;

        if (flags & PB_PART_FLAG_BOOTABLE)
            flags_str[0] = 'B';
        else
            flags_str[0] = '-';

        if (flags & PB_PART_FLAG_OTP)
            flags_str[1] = 'o';
        else
            flags_str[1] = '-';

        if (flags & PB_PART_FLAG_WRITABLE)
            flags_str[2] = 'W';
        else
            flags_str[2] = 'r';

        if (flags & PB_PART_FLAG_ERASE_BEFORE_WRITE)
            flags_str[3] = 'E';
        else
            flags_str[3] = '-';

        printf("%-37s   %-8s   %-7s   %-16s\n", uuid_str, flags_str, size_str,
                                        tbl[i].description);
    }

err_out:
    free(tbl);
    return rc;
}

static int print_bpak_header(struct bpak_header *h,
                             char *part_uuid_str,
                             char *part_description)
{
    printf("Partition: %s (%s)\n", part_uuid_str, part_description);
    printf("Hash:      %s\n", bpak_hash_kind(h->hash_kind));
    printf("Signature: %s\n", bpak_signature_kind(h->signature_kind));

    printf("\nMetadata:\n");
    printf("    ID         Size   Meta ID              Part Ref   Data\n");

    char string_output[128];

    bpak_foreach_meta(h, m)
    {
        if (m->id)
        {
            bpak_meta_to_string(h, m, string_output, sizeof(string_output));
            printf("    %8.8x   %-3u    %-20s ", m->id, m->size,
                         bpak_id_to_string(m->id));

            if (m->part_id_ref)
                printf("%8.8x", m->part_id_ref);
            else
                printf("        ");
            printf("   %s", string_output);
            printf("\n");
        }
    }

    printf("\nParts:\n");
    printf("    ID         Size         Z-pad  Flags          Transport Size\n");

    char flags_str[9] = "--------";

    bpak_foreach_part(h, p)
    {
        if (p->id)
        {
            if (p->flags & BPAK_FLAG_EXCLUDE_FROM_HASH)
                flags_str[0] = 'h';
            else
                flags_str[0] = '-';

            if (p->flags & BPAK_FLAG_TRANSPORT)
                flags_str[1] = 'T';
            else
                flags_str[1] = '-';

            printf("    %8.8x   %-12" PRIu64 " %-3u    %s",
                                    p->id, p->size, p->pad_bytes, flags_str);

            if (p->flags & BPAK_FLAG_TRANSPORT)
                printf("       %-12" PRIu64, p->transport_size);
            else
                printf("       %-12" PRIu64, p->size);

            printf("\n");
        }
    }

    printf("\n\n");
    return 0;
}

static int part_show(struct pb_context *ctx, const char *part_uuid)
{
    struct pb_partition_table_entry *tbl;
    int entries = 128;
    int rc = -PB_RESULT_ERROR;
    char uuid_str[37];

    tbl = malloc(sizeof(struct pb_partition_table_entry) * entries);

    rc = pb_api_partition_read_table(ctx, tbl, &entries);

    if (rc != PB_RESULT_OK)
        goto err_out;

    if (!entries)
        goto err_out;

    for (int i = 0; i < entries; i++)
    {
        struct bpak_header header;
        uuid_unparse(tbl[i].uuid, uuid_str);

        if (part_uuid)
            if (strcmp(uuid_str, part_uuid) != 0)
                continue;

        rc = pb_api_partition_read_bpak(ctx, tbl[i].uuid, &header);

        if (rc == PB_RESULT_OK)
            print_bpak_header(&header, uuid_str, tbl[i].description);
    }

    rc = PB_RESULT_OK;

err_out:
    free(tbl);
    return rc;
}

static int part_dump(struct pb_context *ctx, const char* filename, const char* part_uuid)
{
    struct pb_device_capabilities caps;
    struct pb_partition_table_entry *tbl;
    uuid_t uu_part;
    int partition_table_index = -1;
    size_t chunk_size;
    size_t offset = 0;
    int buffer_id = 0;
    unsigned char* buffer;
    int entries = 128;
    int rc = -PB_RESULT_ERROR;
    char uuid_str[37];
    FILE* fp;
    bool part_is_bpak = false;

    if (part_uuid == 0) {
        return -PB_RESULT_INVALID_ARGUMENT;
    }

    fp = fopen(filename, "wb");

    if (!fp) {
        fprintf(stderr, "Error: Could not open '%s'\n", filename);
        return -PB_RESULT_ERROR;
    }

    /* Read device capabilities */
    rc = pb_api_device_read_caps(ctx, &caps);

    if (rc != PB_RESULT_OK)
        goto err_close_fp;

    if (uuid_parse(part_uuid, uu_part) != 0) {
        fprintf(stderr, "Error: Invalid UUID\n");
        rc = -PB_RESULT_INVALID_ARGUMENT;
        goto err_close_fp;
    }
    chunk_size = caps.chunk_transfer_max_bytes;

    buffer = malloc(chunk_size);
    if (!buffer) {
        rc = -PB_RESULT_NO_MEMORY;
        goto err_close_fp;
    }

    tbl = malloc(sizeof(struct pb_partition_table_entry) * entries);
    if (!tbl) {
        rc = -PB_RESULT_NO_MEMORY;
        goto err_free_buf;
    }

    rc = pb_api_partition_read_table(ctx, tbl, &entries);

    if (rc != PB_RESULT_OK)
        goto err_free_tbl;

    if (!entries)
        goto err_free_tbl;

    for (int i = 0; i < entries; i++) {
        struct bpak_header header;
        uuid_unparse(tbl[i].uuid, uuid_str);

        if (strcmp(uuid_str, part_uuid) != 0)
            continue;

        rc = pb_api_partition_read_bpak(ctx, tbl[i].uuid, &header);

        if (rc == PB_RESULT_OK)
            part_is_bpak = true;
        else if (rc != -PB_RESULT_NOT_FOUND)
            goto err_free_tbl;

        partition_table_index = i;

        break;
    }

    rc = pb_api_stream_init(ctx, uu_part);

    if (rc != PB_RESULT_OK)
    {
        fprintf(stderr, "Error: Stream initialization failed (%i)\n", rc);
        goto err_free_tbl;
    }

    if (part_is_bpak) // TODO: Actual BPAK header extraction
    {
    }

    size_t bytes_left = tbl[partition_table_index].block_size * \
                                (tbl[partition_table_index].last_block - \
                                tbl[partition_table_index].first_block + 1);

    do
    {
        size_t to_read = bytes_left > chunk_size ? chunk_size : bytes_left;
        rc = pb_api_stream_read_buffer(ctx, buffer_id, offset,
                                       to_read, buffer);

        if (rc != PB_RESULT_OK)
            break;

        buffer_id = (buffer_id + 1) % caps.stream_no_of_buffers;

        if (fwrite(buffer, 1, to_read, fp) != to_read)
        {
             rc = -PB_RESULT_ERROR;
             fprintf(stderr, "Error: Write failed\n");
             break;
        }
        offset += to_read;
        bytes_left -= to_read;
    } while (bytes_left > 0);

    pb_api_stream_finalize(ctx);

err_free_tbl:
    free(tbl);
err_free_buf:
    free(buffer);
err_close_fp:
    fclose(fp);
    return rc;
}

int action_part(int argc, char **argv)
{
    int opt;
    int long_index = 0;
    int rc = 0;
    const char *transport = NULL;
    const char *device_uuid = NULL;
    struct pb_context *ctx = NULL;
    bool flag_list = false;
    bool flag_install = false;
    bool flag_write = false;
    bool flag_verify = false;
    bool flag_erase = false;
    bool flag_show = false;
    bool flag_dump = false;
    int install_variant = 0;
    const char *part_uuid = NULL;
    uuid_t part_uu;
    const char *filename = NULL;

    struct option long_options[] =
    {
        {"help",        no_argument,       0,  'h' },
        {"verbose",     no_argument,       0,  'v' },
        {"transport",   required_argument, 0,  't' },
        {"device",      required_argument, 0,  'd' },
        {"write",       required_argument, 0,  'w' },
        {"verify",      required_argument, 0,  'c' },
        {"erase",       no_argument,       0,  'e' },
        {"show",        no_argument,       0,  's' },
        {"part",        required_argument, 0,  'p' },
        {"install",     no_argument,       0,  'i' },
        {"variant",     required_argument, 0,  'I' },
        {"list",        no_argument,       0,  'l' },
        {"dump",        required_argument, 0,  'D' },
        {"force",       no_argument,       0,  'F' },
        {0,             0,                 0,   0  }
    };

    while ((opt = getopt_long(argc, argv, "hvt:w:silp:c:d:D:I:e",
                   long_options, &long_index )) != -1)
    {
        switch (opt)
        {
            case 'h':
                help_part();
                return 0;
            case 'v':
                pb_inc_verbosity();
            break;
            case 't':
                transport = (const char *) optarg;
            break;
            case 'l':
                flag_list = true;
            break;
            case 'i':
                flag_install = true;
            break;
            case 'I':
                flag_install = true;
                install_variant = strtol(optarg, NULL, 0);
            break;
            case 'w':
                flag_write = true;
                filename = (const char *) optarg;
            break;
            case 'c':
                flag_verify = true;
                filename = (const char *) optarg;
            break;
            case 'e':
                flag_erase = true;
            break;
            case 'D':
                flag_dump = true;
                filename = (const char *) optarg;
            break;
            case 'p':
                part_uuid = (const char *) optarg;
            break;
            case 's':
                flag_show = true;
            break;
            case 'd':
                device_uuid = (const char *) optarg;
            break;
            case '?':
                fprintf(stderr, "Unknown option: %c\n", optopt);
                return -1;
            break;
            case ':':
                fprintf(stderr, "Missing arg for %c\n", optopt);
                return -1;
            break;
            default:
               return -1;
        }
    }

    if (argc <= 1)
    {
        help_part();
        return 0;
    }

    if (part_uuid != NULL) {
        if (uuid_parse(part_uuid, part_uu) != 0) {
            fprintf(stderr, "Error: Invalid UUID\n");
            return -PB_RESULT_INVALID_ARGUMENT;
        }
    }

    rc = transport_init_helper(&ctx, transport, device_uuid);

    if (rc != PB_RESULT_OK)
    {
        fprintf(stderr, "Error: Could not initialize context\n");
        return rc;
    }

    rc = ctx->connect(ctx);

    if (rc != PB_RESULT_OK)
    {
        fprintf(stderr, "Error: Could not connect to device\n");
        goto err_free_ctx_out;
    }

    if ((flag_write && !part_uuid) ||
        (flag_dump && !part_uuid)  ||
        (flag_verify && !part_uuid) ||
        (flag_erase && !part_uuid)) {
        fprintf(stderr, "Error: missing required --part argument\n");
        goto err_free_ctx_out;
    }

    if (flag_list)
        rc = part_list(ctx);
    else if (flag_install)
        rc = pb_api_partition_install_table(ctx, part_uu, install_variant);
    else if (flag_write)
        rc = part_write(ctx, filename, part_uuid);
    else if (flag_verify)
        rc = part_verify(ctx, filename, part_uuid);
    else if (flag_erase)
        rc = pb_api_partition_erase(ctx, part_uu);
    else if (flag_show)
        rc = part_show(ctx, part_uuid);
    else if (flag_dump)
        rc = part_dump(ctx, filename, part_uuid);

    if (rc != PB_RESULT_OK) {
        fprintf(stderr, "Error: Command failed %i (%s)\n", rc,
                            pb_error_string(rc));
    }

err_free_ctx_out:
    pb_api_free_context(ctx);
    return rc;
}
