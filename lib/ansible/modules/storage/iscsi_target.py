#!/usr/bin/python3
# -*- coding: utf-8 -*-


import sys
import logging
import traceback
from pprint import pformat
from collections import defaultdict
from operator import attrgetter

import rtslib_fb
from ansible.module_utils.basic import AnsibleModule


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}


DOCUMENTATION = '''
---
module: iscsi_target

short_description: Manage ISCSI target

version_added: "2.4"

description:
    - This module handles the setup of ISCSI targets on block device and/or file objects, which then can be accessed using the open_iscsi module.

author:
    - Łukasz Bednarczyk

requirements:
    - 'rtslib-fb'
'''


EXAMPLES = '''
# Setup a new target
- name:
'''


logger = logging.getLogger(__name__)


class InvalidParameter(Exception):
    '''
    An Exception class with a 'message' attribute (following rtslib_fb.utils.RTSLibError).
    '''

    def __init__(self, message):
        self.message = message
        super(InvalidParameter, self).__init__(message)


class Ansible2RTSLib(object):
    '''
    Provide Ansible with an interface to the RTSLib.
    '''

    DEFAULT_PORTAL_LIST = ({'ip': '0.0.0.0', 'port': 3260}, )

    MAP_STCLASS2STNAME = [
        (rtslib_fb.FileIOStorageObject, 'ifile'),
        (rtslib_fb.BlockStorageObject, 'iblock'),
    ]

    MAPS_STNAME2STCLASS = map(lambda x: tuple(reversed(x)), MAP_STCLASS2STNAME)

    BLOCKSIZE_FIX = 4096

    @classmethod
    def apply(cls, module, opts):
        '''
        Apply module parameters on the ISCSI target infrastucture.
        '''
        logger.debug('PARAMS: {}'.format(pformat(module.params)))
        result = {'changed': False}
        if not module.check_mode:
            if 'info' == opts.get('state'):
                # Info is always collected at the end, skipping here
                pass
            elif 'present' == opts.get('state'):
                result.update(cls._update_iscsi_objects(target_wwn=opts['wwn'],
                                                        devices_list=opts['devices'],
                                                        portals_list=opts['portals'],
                                                        initiators_list=opts['initiators']))
            elif 'absent' == opts.get('state'):
                assert opts['wwn']  # must not be empty
                logger.warning('REMOVING TARGET: {}'.format(opts['wwn']))
                rtslib_fb.Target(rtslib_fb.FabricModule('iscsi'), wwn=opts['wwn'], mode='lookup').delete()
                result['changed'] = True
            else:
                raise InvalidParameter('invalid parameter for state: {}'.format(opts.get('state')))
        result.update(cls._get_iscsi_objects_info())
        return result

    @classmethod
    def _parse_lun(cls, obj):
        '''
        Retrieve and neatly organise available information on a specified LUN.
        '''
        for klass, name in cls.MAP_STCLASS2STNAME:
            if issubclass(obj.storage_object.__class__, klass):
                storage_klass_ident = name
                break
        else:
            raise InvalidParameter('not supported storage class: {}'.format(obj.__class__.__name__))
        parse_result = {
            'device_path': obj.storage_object.udev_path,
            'storage_type': storage_klass_ident,
        }
        if 'ifile' == storage_klass_ident:
            parse_result['device_size'] = obj.storage_object.size
        return parse_result

    @classmethod
    def _get_iscsi_objects_info(cls):
        '''
        Return a description of existing ISCSI target objects following the convention
        of module parametrs.
        '''
        result = defaultdict(list)
        for target in rtslib_fb.RTSRoot().targets:
            for tpg in target.tpgs:
                lun_data = [cls._parse_lun(l) for l in sorted(tpg.luns, key=attrgetter('lun'))]
                portal_data = [{'ip': p.ip_address, 'port': p.port, } for p in tpg.network_portals]
                result[target.wwn].append({'devices': lun_data, 'portals': portal_data, })
        return {'info': dict(result), }

    @classmethod
    def _update_iscsi_objects(cls, target_wwn, devices_list, portals_list, initiators_list):
        '''
        Try to either create necessary objects or update as closely as possible
        according to specified module parameters.
        '''
        # Decide wrether to create a new target or stick with an existing one if any matching WWNs exist
        try:
            # Target lookup case
            if not target_wwn:
                # Currently no attempt is made in case of a null target_wwn to match the specified
                # device/portal/initiator combination with existing targets/TPGSs!
                raise IndexError('immediately jump to the target creation case')
            target = [t for t in rtslib_fb.RTSRoot().targets if target_wwn == t.wwn][0]
        except IndexError:
            # Target creation case
            target = rtslib_fb.Target(rtslib_fb.FabricModule('iscsi'), wwn=target_wwn)
        logger.debug('ISCSI TARGET: {}'.format(pformat(target.dump())))
        # Currenly modyfying of a multiple number of TPGs is not supported!
        assert 2 > len(list(target.tpgs))
        # Try to update the first TPG or create a new one in case none exist
        try:
            tpg = tuple(target.tpgs)[0]
        except IndexError:
            tpg = rtslib_fb.TPG(target, tag=1)
        # logger.debug('ISCSI TPG: {}'.format(pformat(tpg.dump())))
        # Create misssing portals, remove those not specified
        superfluous_portal_defs = {(p.ip_address, p.port) for p in tpg.network_portals} - {(p['ip'], p['port']) for p in portals_list}
        for check_portal in tpg.network_portals:
            if (check_portal.ip_address, check_portal.port) in superfluous_portal_defs:
                logger.warn('REMOVE ISCSI PORTAL: {}'.format(pformat(check_portal.dump())))
                check_portal.delete()
        for portal_def in portals_list:
            portal = tpg.network_portal(ip_address=portal_def['ip'], port=portal_def['port'])
            logger.debug('ISCSI PORTAL: {}'.format(pformat(portal.dump())))
        # Create missing storage objects and LUNs, remove those not specified.
        # StorageObject names must be unique within given Backstore, so we do have to delete aggresively.
        tpg_luns_set = {(l.lun,
                         l.storage_object.name,
                         l.storage_object.__class__,
                         getattr(l.storage_object, 'size', 0),
                         l.storage_object.udev_path) for l in tpg.luns}
        device_luns_set = {(i,
                            d.get('device_name', 'iscsibackstore{}'.format(i)),
                            dict(cls.MAPS_STNAME2STCLASS)[d['storage_type']],
                            d.get('device_size', 0),
                            d['device_path']) for i, d in enumerate(devices_list)}
        for olun_lun, ostor_name, ostor_class, ostor_size, ostor_dev in tpg_luns_set - device_luns_set:
            logger.warn('REMOVE LUN: {}'.format(pformat(tpg.lun(olun_lun).dump())))
            tpg.lun(olun_lun).delete()
            logger.warn('REMOVE LUN: {}'.format(pformat(ostor_class(ostor_name).dump())))
            ostor_class(ostor_name).delete()
        for nlun_lun, nstor_name, nstor_class, nstor_size, nsttor_dev in device_luns_set - tpg_luns_set:
            if rtslib_fb.FileIOStorageObject == nstor_class:
                storage_obj = nstor_class(nstor_name, dev=nsttor_dev, size=nstor_size)
            else:
                storage_obj = nstor_class(nstor_name, dev=nsttor_dev)
            logger.debug('ISCSI SO: {}'.format(pformat(storage_obj.dump())))
            lun = tpg.lun(lun=nlun_lun, storage_object=storage_obj)
            logger.debug('ISCSI LUN: {}'.format(pformat(lun.dump())))
        # Create initiators and rmeove those not specified:
        for tpg_initiator in initiators_list:
            nodeacl = tpg.node_acl(tpg_initiator['wwn'])  # TODO: tpg_initiator access policy
            # logger.debug('ISCSI ACL: {}'.format(pformat(nodeacl.dump())))
        # TODO: mappedluns!
        tpg.enable = True  # Disregard current state and always enable the default TPG
        return {'changed': True, }

    @staticmethod
    def _get_or_create_iscsi_storage_object(storage_type, device_name, device_path, device_size=0):
        '''
        Try to reuse existing ISCSI devices and optionally create a new object according to parameters.
        '''
        if 'ifile' == storage_type:
            try:
                fioso = rtslib_fb.FileIOStorageObject(device_name)
                if device_size and fioso.size != device_size:
                    # FIXME: Currently there is no solution for this problem!
                    logger.warn('Device size differs from provided!')
            except rtslib_fb.utils.RTSLibNotInCFS:
                assert device_size
                fioso = rtslib_fb.FileIOStorageObject(device_name, dev=device_path, size=device_size)
            logger.debug('ISCSI FIOSO: {}'.format(fioso.dump()))
            return fioso
        elif 'iblock' == storage_type:
            try:
                bso = rtslib_fb.BlockStorageObject(device_name)
            except rtslib_fb.utils.RTSLibNotInCFS:
                bso = rtslib_fb.BlockStorageObject(device_name, dev=device_path)
            logger.debug('ISCSI BSO: {}'.format(bso.dump()))
            return bso
        else:
            raise InvalidParameter('not supported device type: {}'.format(storage_type))


def run_module():
    module_args = dict(
        state=dict(required=True, stype=str),
        wwn=dict(required=False, type=str),
        portals=dict(required=False, type=list, default=Ansible2RTSLib.DEFAULT_PORTAL_LIST),
        initiators=dict(required=False, type=list, default=[]),
        devices=dict(required=False, type=list, default=[])
    )

    result = dict(
        changed=False,
        original_message='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    try:
        result = Ansible2RTSLib.apply(module, opts=module.params)
    except (InvalidParameter, rtslib_fb.utils.RTSLibError) as error:
        # The class rtslib_fb.utils.RTSLibError does have a 'message' attribute.
        logger.error('EXCEPTION: [{}] {}'.format(error.__class__.__name__, error.message))
        module.fail_json(msg=error.message, exception=traceback.format_exc())
    except Exception as error:
        logger.error('UNHANDLED EXCEPTION: [{}] {}'.format(error.__class__.__name__, str(error)))
        module.fail_json(msg=str(error), exception=traceback.format_exc())
    else:
        assert result is not None
        logger.debug('RESULT: {}'.format(pformat(result)))
        module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
    main()
