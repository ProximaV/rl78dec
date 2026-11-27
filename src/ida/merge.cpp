#include <ida.hpp>
#include <idp.hpp>
#include <mergemod.hpp>

#include "merge.hpp"
#include "db.hpp"

namespace rl78dec {

namespace {

static const idbattr_info_t kRl78decIdbAttrs[] = {
    IDI_ALTENTRY(0, atag, sizeof(uval_t), 0, nullptr, "Sync with disassembly"),
    IDI_ALTENTRY(1, atag, sizeof(uval_t), 0, nullptr, "Hide scalar casts"),
};

SIMPLE_MODDATA_DIFF_HELPER(
    g_rl78dec_modmerger_helper,
    "RL78 Decompiler options",
    idadb::RL78DEC_NODE_NAME,
    kRl78decIdbAttrs);

static const merge_node_info_t kRl78decMergeNodes[] = {
    {"Function annotations", stag, NDS_IS_STR, nullptr},
};

} // namespace

void register_rl78dec_merge_handlers(merge_data_t &md, int moddata_id) {
    if (moddata_id < 0) return;
    DEFINE_PLUGIN_MH_PARAMS("RL78 Decompiler (rl78dec)", MH_UI_COLONNAME);
    create_std_modmerge_handlers(mhp, moddata_id, g_rl78dec_modmerger_helper);

    mhp.mh_flags = MH_UI_COMMANAME | MH_UI_NODETAILS;
    create_nodeval_merge_handlers(
        nullptr,
        mhp,
        moddata_id,
        idadb::RL78DEC_NODE_NAME,
        kRl78decMergeNodes,
        qnumber(kRl78decMergeNodes));
}

} // namespace rl78dec
