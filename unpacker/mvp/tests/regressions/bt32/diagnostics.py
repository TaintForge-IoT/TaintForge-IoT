"""Native UNKNOWN classifications; proof statuses are preserved."""
import re


def classify(native):
    status, reason = native.get('status'), native.get('reason')
    result = {'native_status': status, 'reason': reason,
              'replay_build': native.get('replay_build'),
              'collector': native.get('collector'), 'bucket': 'unclassified'}
    if status == 'OBSERVED':
        result['bucket'] = 'observed_prefix'
        return result
    if status == 'BOUNDARY_WITNESS':
        result['bucket'] = 'witness_requiring_concrete_validation'
        return result
    if status == 'UNSAT':
        result['bucket'] = 'unsat_selected_model'
        return result
    if status != 'UNKNOWN':
        result['bucket'] = 'invalid_native_status'
        return result
    build, collector = native.get('replay_build'), native.get('collector')
    if build is not None:
        if not isinstance(build, dict) or type(build.get('status')) is not int or \
                type(build.get('issues')) is not int:
            result['bucket'] = 'invalid_replay_diagnostics'
        elif build['status'] in (3, 4):
            result['bucket'] = 'replay_resource_limit'
        elif build['status'] == 2:
            result['bucket'] = 'invalid_replay'
        elif build['status'] == 1:
            if build['issues'] & (1 << 12):
                result['bucket'] = 'syscall_model_gap'
            elif build['issues'] & (1 << 11):
                result['bucket'] = 'syscall_observation_gap'
            elif build['issues'] & 8:
                stop = build.get('stopped_origin')
                located = (isinstance(stop, dict) and type(stop.get('pc')) is int and
                           0 <= stop['pc'] <= 0xffffffff and
                           isinstance(stop.get('bytes'), str) and len(stop['bytes']) % 2 == 0 and
                           re.fullmatch('[0-9a-f]{2,30}', stop['bytes']) is not None)
                result['bucket'] = 'unsupported_instruction' if located else 'unsupported_replay_unlocalized'
            else:
                result['bucket'] = 'replay_evidence_or_model_gap'
        elif build['status'] == 0 and build['issues'] == 0:
            result['bucket'] = ('inversion_resource_limit' if reason == 'inversion_resource_limit' else
                                'inversion_unknown' if str(reason).startswith('inversion_') else
                                'post_lift_unknown')
        else:
            result['bucket'] = 'invalid_replay_diagnostics'
    elif isinstance(collector, dict) and \
            type(collector.get('requested_occurrence')) is int and \
            type(collector.get('observed_occurrences')) is int and \
            0 <= collector['observed_occurrences'] < collector['requested_occurrence'] and \
            collector.get('armed') is True:
        result['bucket'] = 'requested_occurrence_unobserved_in_collected_prefix'
        result['evidence_scope'] = 'collected_prefix_only; no claim about later execution'
    else:
        result['bucket'] = ('replay_unknown_without_location' if reason == 'replay_incomplete' else
                            'collector_stop_unlocalized' if reason == 'unsupported_syscall_prefix' else
                            'unknown_without_build_diagnostics')
    return result
